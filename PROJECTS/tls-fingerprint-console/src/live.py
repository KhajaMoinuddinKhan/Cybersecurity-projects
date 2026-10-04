"""Turning a live packet stream into events, as the packets arrive.

The file path in src/pipeline.py reads a whole capture, reassembles it and then
fingerprints. Live capture cannot work that way: packets arrive one at a time,
a ClientHello can be split across several TCP segments, and the console has to
say something while the connection is still open rather than after it closes.

So this module keeps a small table of in-flight flows and fingerprints each one
as soon as enough bytes have arrived to try. A flow is emitted when its
ClientHello has been read and either the server has answered or a short grace
period has passed, so the server-side fingerprints are usually included without
holding the client fingerprint back for long.
"""
from __future__ import annotations

import time

from . import ja3 as ja3mod
from . import ja4 as ja4mod
from . import tls as tlsmod
from .pipeline import _first, _handshake_records

try:  # QUIC support is optional: it needs a crypto library for the AEAD
    from . import quic
except Exception:  # pragma: no cover - import guard
    quic = None

# How long to wait for a server response after a ClientHello before emitting
# the event anyway. Long enough to catch a handshake on a slow link, short
# enough that a one-sided flow still shows up promptly.
DEFAULT_GRACE = 2.0

# A flow is forgotten if nothing arrives for this long.
DEFAULT_TTL = 180.0

# Per-direction buffer ceiling. A TLS handshake is a few kilobytes; this is
# generous, and it stops a long-lived encrypted connection from growing the
# buffer without bound, since the bytes after the handshake are ciphertext we
# will never read.
MAX_BUFFER = 262144

# How many flows to track at once before the oldest are dropped.
MAX_FLOWS = 4096


class LiveSensor:
    """Feed it packets, get events and alerts back."""

    def __init__(self, store, corpus, rules_module=None, os_by_ja3=None,
                 grace=DEFAULT_GRACE, ttl=DEFAULT_TTL, on_event=None, on_alert=None):
        if rules_module is None:
            from . import rules as rules_module
        self.store = store
        self.corpus = corpus
        self.rules = rules_module
        self.os_by_ja3 = os_by_ja3 if os_by_ja3 is not None else _os_map(corpus)
        self.grace = grace
        self.ttl = ttl
        self.on_event = on_event
        self.on_alert = on_alert
        self.flows = {}
        # The sensor runs on the packet clock, not the wall clock. A live
        # capture's timestamps track real time closely enough that the two agree,
        # but a replayed capture carries the timestamps of when it was recorded,
        # and judging those against the wall clock expired every flow the
        # instant it was created.
        self.clock = None
        # QUIC ClientHellos are split across Initial packets, so the sensor has
        # to reassemble a CRYPTO stream per connection rather than fingerprint
        # a single datagram.
        self._quic_assembler = None
        self.counters = {"packets": 0, "bytes": 0, "flows": 0, "events": 0,
                         "alerts": 0, "expired": 0, "dropped": 0}

    # ------------------------------------------------------------------ feed

    def feed(self, packet):
        """Take one decoded packet; return the events it completed."""
        if not isinstance(packet, dict):
            return []
        self.counters["packets"] += 1
        payload = packet.get("payload") or b""
        self.counters["bytes"] += len(payload)

        if packet.get("protocol") == "udp":
            return self._feed_quic(packet, payload)
        if packet.get("protocol") != "tcp":
            return []

        src = (packet.get("src_ip"), packet.get("src_port"))
        dst = (packet.get("dst_ip"), packet.get("dst_port"))
        if not all(isinstance(x, str) for x in (src[0], dst[0])):
            return []
        key = tuple(sorted([src, dst]))
        flow = self.flows.get(key)
        if flow is None:
            flow = self._new_flow(key, src, dst, packet.get("ts"))
            self.flows[key] = flow
            self.counters["flows"] += 1
            if len(self.flows) > MAX_FLOWS:
                self._drop_oldest()
        ts = packet.get("ts")
        if isinstance(ts, (int, float)):
            self.clock = ts if self.clock is None else max(self.clock, ts)
        flow["last_ts"] = self.clock if self.clock is not None else time.time()

        # A bare SYN carries the TCP options JA4T is built from.
        flags = packet.get("flags") or ""
        if "S" in flags and "A" not in flags and "ja4t" not in flow["fingerprints"]:
            try:
                flow["fingerprints"]["ja4t"] = ja4mod.ja4t(tlsmod.parse_tcp_syn(packet))
                flow["client"] = src
                flow["server"] = dst
            except Exception:
                pass

        if payload:
            buf = flow["buf"].setdefault(src, bytearray())
            # Trim rather than append-then-stop, so the ceiling is a real
            # ceiling instead of one payload's worth of overshoot.
            if len(buf) < MAX_BUFFER:
                buf.extend(payload[:MAX_BUFFER - len(buf)])
            self._fingerprint(flow)

        return self._ready(self._now())

    # ------------------------------------------------------------------ tick

    def tick(self):
        """Advance the clock to now and return any events whose grace has passed.

        For a live capture this is what releases a flow whose server never
        answered: packets keep arriving from elsewhere, so the clock keeps
        moving and the grace period on the silent flow still expires.
        """
        self.clock = max(self.clock, time.time()) if self.clock is not None else time.time()
        return self._ready(self.clock)

    def _now(self):
        """The current position of the packet clock."""
        return self.clock if self.clock is not None else time.time()

    def flush(self):
        """Emit everything still held, as at shutdown.

        A flow is only emitted if it was identified -- that is, if a
        ClientHello or an HTTP request was actually read. Without that check
        flush released a bare SYN, whose only fingerprint is the JA4T, and the
        console would report a handshake that never happened. _ready has always
        required this; flush did not, and the two disagreed.
        """
        out = []
        for flow in list(self.flows.values()):
            if flow["fingerprints"] and flow["hello_ts"] is not None and not flow["emitted"]:
                out.extend(self._emit(flow))
        self.flows.clear()
        return out

    # -------------------------------------------------------------- internals

    def _new_flow(self, key, src, dst, ts):
        return {
            "key": key, "client": None, "server": None,
            "buf": {}, "first_ts": ts if isinstance(ts, (int, float)) else time.time(),
            "last_ts": ts if isinstance(ts, (int, float)) else time.time(),
            "hello_ts": None, "fingerprints": {}, "sni": None, "alpn": None,
            "user_agent": None, "emitted": False, "answered": False,
        }

    def _drop_oldest(self):
        oldest = sorted(self.flows.items(), key=lambda kv: kv[1]["last_ts"])[:len(self.flows)//8 or 1]
        for k, _ in oldest:
            self.flows.pop(k, None)
            self.counters["dropped"] += 1

    def _feed_quic(self, packet, payload):
        """Fingerprint a QUIC datagram, if it is one we can read.

        QUIC is TLS over UDP, and its Initial packets can be decrypted by
        anyone: the keys come from a public salt and the connection ID, which
        is why a passive observer can fingerprint HTTP/3 at all. A datagram
        that is not QUIC, or whose Initial packet does not decrypt, produces
        nothing -- and produces it quietly, because most UDP is not QUIC.
        """
        if not payload or quic is None or not quic.HAVE_CRYPTO:
            return []
        if self._quic_assembler is None:
            try:
                self._quic_assembler = quic.CryptoAssembler()
            except Exception:
                return []
        try:
            found = self._quic_assembler.feed(payload)
        except Exception:
            return []
        if not found:
            return []
        try:
            hello = tlsmod.parse_client_hello(found["client_hello"])
        except Exception:
            return []
        if not hello:
            return []

        ts = packet.get("ts")
        if isinstance(ts, (int, float)):
            self.clock = ts if self.clock is None else max(self.clock, ts)
        now = self._now()

        fingerprints = {}
        for kind, fn in (("ja3", ja3mod.ja3), ("ja4", ja4mod.ja4)):
            try:
                fingerprints[kind] = fn(hello, proto="q")
            except TypeError:
                # ja3 takes no protocol argument: QUIC carries the same client
                # hello fields, so the same hash applies.
                try:
                    fingerprints[kind] = fn(hello)
                except Exception:
                    pass
            except Exception:
                pass
        if not fingerprints:
            return []

        alpn = hello.get("alpn") or []
        event = {
            "ts": ts if isinstance(ts, (int, float)) else now,
            "src_ip": packet.get("src_ip"), "src_port": packet.get("src_port"),
            "dst_ip": packet.get("dst_ip"), "dst_port": packet.get("dst_port"),
            "sni": hello.get("sni"),
            "alpn": (alpn[0].decode("ascii", "replace")
                     if alpn and isinstance(alpn[0], bytes) else (alpn[0] if alpn else None)),
            "user_agent": None,
            "fingerprints": fingerprints,
            "transport": "quic",
            "quic_version": found.get("version"),
            "live": True,
        }
        if hello.get("ech"):
            event["ech"] = True
        return self._publish(event)

    def _fingerprint(self, flow):
        """Try to read a handshake out of whatever bytes have arrived so far.

        The ClientHello is looked for independently of whether a client has
        already been identified. Identifying the client from the TCP SYN (which
        is where JA4T comes from) used to set the client early and skip this
        branch entirely, so the two most valuable fingerprints in the console
        were the two it never produced for a live flow.
        """
        # ---- 1. the ClientHello, which names the client side
        if "ja3" not in flow["fingerprints"] or "ja4" not in flow["fingerprints"]:
            for endpoint, buf in list(flow["buf"].items()):
                data = bytes(buf)
                if not data:
                    continue
                try:
                    records = _handshake_records(data)
                except Exception:
                    continue
                body = _first(records, 1)
                if body is None:
                    continue
                try:
                    hello = tlsmod.parse_client_hello(body)
                except Exception:
                    continue
                if not hello:
                    continue
                flow["client"] = endpoint
                flow["server"] = (flow["key"][1] if endpoint == flow["key"][0]
                                  else flow["key"][0])
                flow["hello_ts"] = flow["hello_ts"] or self._now()
                flow["sni"] = hello.get("sni")
                if hello.get("ech"):
                    flow["ech"] = True
                alpn = hello.get("alpn") or []
                if alpn:
                    first = alpn[0]
                    flow["alpn"] = (first.decode("ascii", "replace")
                                    if isinstance(first, bytes) else str(first))
                for kind, fn in (("ja3", ja3mod.ja3), ("ja4", ja4mod.ja4)):
                    try:
                        flow["fingerprints"][kind] = fn(hello)
                    except Exception:
                        pass
                break

        # ---- 2. the server side of the same flow
        for endpoint, buf in list(flow["buf"].items()):
            if endpoint == flow["client"]:
                continue
            data = bytes(buf)
            if not data:
                continue
            try:
                records = _handshake_records(data)
            except Exception:
                continue
            sh = _first(records, 2)
            if sh is not None and "ja3s" not in flow["fingerprints"]:
                try:
                    shello = tlsmod.parse_server_hello(sh)
                except Exception:
                    shello = None
                if shello:
                    flow["answered"] = True
                    for kind, fn in (("ja3s", ja3mod.ja3s), ("ja4s", ja4mod.ja4s)):
                        try:
                            flow["fingerprints"][kind] = fn(shello)
                        except Exception:
                            pass
            cert = _first(records, 11)
            if cert is not None and "ja4x" not in flow["fingerprints"]:
                try:
                    certs = tlsmod.parse_certificate_message(cert)
                    if certs:
                        flow["fingerprints"]["ja4x"] = ja4mod.ja4x(certs[0])
                except Exception:
                    pass

        # ---- 3. a plaintext HTTP request, the only source of a JA4H
        if "ja4h" not in flow["fingerprints"]:
            for endpoint, buf in list(flow["buf"].items()):
                if flow["fingerprints"].get("ja4"):
                    continue  # a TLS flow: the request is inside the ciphertext
                try:
                    req = tlsmod.parse_http_request(bytes(buf))
                except Exception:
                    continue
                try:
                    flow["fingerprints"]["ja4h"] = ja4mod.ja4h(req)
                except Exception:
                    continue
                for name, value in (req.get("headers") or []):
                    if name.lower() == "user-agent":
                        flow["user_agent"] = value
                        break
                if flow["client"] is None:
                    flow["client"] = endpoint
                    flow["server"] = (flow["key"][1] if endpoint == flow["key"][0]
                                      else flow["key"][0])
                # A plaintext HTTP flow has no handshake, so the request is its
                # identifying moment and what starts its grace period.
                flow["hello_ts"] = flow["hello_ts"] or self._now()
                break

    def _ready(self, now):
        """Emit what is ready, then retire what is stale.

        Emission is decided before expiry on purpose. A flow that has been
        fingerprinted is the only thing this sensor exists to produce, and
        retiring it on age before checking whether it was ready threw away
        every event in a replayed capture, where the packet clock and the wall
        clock are years apart.
        """
        out = []
        for key, flow in list(self.flows.items()):
            idle = now - flow["last_ts"]
            stale = idle > self.ttl

            if not flow["emitted"] and flow["fingerprints"] and flow["hello_ts"] is not None:
                # Emit once the flow goes quiet, not the moment the server
                # answers: the ServerHello and the Certificate are separate
                # packets, so a flow released at the first of them lost its
                # JA4X. The hard cap keeps a connection that streams without
                # pause from being held for ever.
                since_hello = now - flow["hello_ts"]
                if (flow["answered"] and idle >= self.grace) or since_hello >= self.grace * 2:
                    out.extend(self._emit(flow))

            if stale:
                self.flows.pop(key, None)
                self.counters["expired"] += 1
        return out

    def _emit(self, flow):
        """Build an event from a TCP flow and publish it."""
        client = flow["client"] or ("", 0)
        server = flow["server"] or ("", 0)
        event = {
            "ts": flow["hello_ts"] or flow["first_ts"],
            "src_ip": client[0], "src_port": client[1],
            "dst_ip": server[0], "dst_port": server[1],
            "sni": flow["sni"], "alpn": flow["alpn"],
            "user_agent": flow["user_agent"],
            "fingerprints": dict(flow["fingerprints"]),
            "transport": "tcp",
            "live": True,
        }
        if flow.get("ech"):
            event["ech"] = True
        flow["emitted"] = True
        return self._publish(event)

    def _publish(self, event):
        """Label, judge, store and announce one event.

        Split out from _emit because QUIC builds its event directly -- there is
        no flow table for a datagram -- and both paths have to run the same
        intel lookup, the same rules and the same callbacks. Handing a
        ready-made event to _emit used to fail, because _emit expects a flow.
        """
        for kind, value in (event.get("fingerprints") or {}).items():
            try:
                entry = self.corpus.match(kind, value) if self.corpus is not None else None
            except Exception:
                entry = None
            if entry is not None:
                event["category"] = getattr(entry, "category", None)
                event["intel_name"] = getattr(entry, "name", None)
                break

        self.counters["events"] += 1
        try:
            produced = self.rules.evaluate(event, self._ctx()) or []
        except Exception:
            produced = []
        try:
            self.store.add_event(event)
        except Exception:
            pass
        alerts = []
        for alert in produced:
            alert = dict(alert)
            alert.setdefault("src_ip", event.get("src_ip"))
            alert.setdefault("sni", event.get("sni"))
            alert.setdefault("ts", event.get("ts"))
            try:
                self.store.add_alert(alert)
            except Exception:
                pass
            alerts.append(alert)
            self.counters["alerts"] += 1
        if self.on_event:
            try:
                self.on_event(event)
            except Exception:
                pass
        if self.on_alert:
            for a in alerts:
                try:
                    self.on_alert(a)
                except Exception:
                    pass
        return [event] + alerts

    def _ctx(self):
        return {"store": self.store, "corpus": self.corpus,
                "seen_before": self.store.seen_before, "os_by_ja3": self.os_by_ja3}

    def stats(self):
        s = dict(self.counters)
        s["in_flight"] = len(self.flows)
        return s


def _os_map(corpus):
    """The JA3 to OS family map, built the same way the app builds it."""
    try:
        from .app import os_by_ja3
        return os_by_ja3(corpus)
    except Exception:
        return {}
