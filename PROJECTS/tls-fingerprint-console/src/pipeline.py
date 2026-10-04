"""Ties capture to fingerprints to events.

This is the glue the console needs and the part a reader is most likely to
ask about: it turns bytes on the wire into the event dict the rules and the
store speak.  Nothing here opens a socket -- it reads a capture file, so the
whole path is reproducible and testable.
"""
from __future__ import annotations

from . import ja3 as ja3mod
from . import ja4 as ja4mod
from . import pcap as pcapmod
from . import tls as tlsmod

try:  # QUIC needs a crypto library for the AEAD; the rest works without it
    from . import quic
except Exception:  # pragma: no cover - import guard
    quic = None


def _handshake_records(payload):
    """Every handshake message in a byte stream, as (msg_type, body)."""
    out = []
    for rec in tlsmod.iter_tls_records(payload):
        # 22 is the handshake content type
        if rec.get("record_type") != 22:
            continue
        body = rec.get("body") or b""
        p = 0
        while p + 4 <= len(body):
            msg_type = body[p]
            length = int.from_bytes(body[p + 1:p + 4], "big")
            chunk = body[p + 4:p + 4 + length]
            if len(chunk) < length:
                break
            out.append((msg_type, chunk))
            p += 4 + length
    return out


def _first(records, msg_type):
    for mt, body in records:
        if mt == msg_type:
            return body
    return None


def _flow_key(a, b):
    """An order-independent key for a bidirectional flow."""
    return tuple(sorted([a, b]))


def fingerprint_streams(packets):
    """Group a packet list into flows and fingerprint each one.

    Returns a list of dicts carrying the flow's endpoints, the fingerprints we
    could compute, and the SNI / ALPN / User-Agent we could read out.
    """
    streams = pcapmod.reassemble_streams(packets)

    # bucket every direction by flow
    flows = {}
    for s in streams:
        a = (s["src_ip"], s["src_port"])
        b = (s["dst_ip"], s["dst_port"])
        key = _flow_key(a, b)
        flows.setdefault(key, {"a": a, "b": b, "dirs": {}})
        flows[key]["dirs"][(s["src_ip"], s["src_port"])] = s.get("payload") or b""

    # TCP SYN options, per client endpoint, for JA4T
    syns = {}
    for p in packets:
        if p.get("protocol") != "tcp":
            continue
        if "S" in (p.get("flags") or "") and "A" not in (p.get("flags") or ""):
            syns.setdefault((p["src_ip"], p["src_port"]), p)

    results = []
    for key, flow in flows.items():
        rec = {
            "client": None, "server": None,
            "fingerprints": {}, "sni": None, "alpn": None, "user_agent": None,
            "ts": None,
        }
        # whichever direction carried a ClientHello is the client
        for endpoint, payload in flow["dirs"].items():
            if rec["client"] is not None:
                continue
            records = _handshake_records(payload)
            if _first(records, 1) is not None:
                rec["client"] = endpoint
                rec["server"] = flow["b"] if endpoint == flow["a"] else flow["a"]

        if rec["client"] is None:
            # No ClientHello: this may still be a plaintext HTTP flow, which is
            # the only place a JA4H can come from when nothing is decrypted.
            for endpoint, payload in flow["dirs"].items():
                try:
                    req = tlsmod.parse_http_request(payload)
                except Exception:
                    continue
                rec["client"] = endpoint
                rec["server"] = flow["b"] if endpoint == flow["a"] else flow["a"]
                rec["http"] = req
                break
            if rec["client"] is None:
                continue

        client_payload = flow["dirs"].get(rec["client"], b"")
        server_payload = flow["dirs"].get(rec["server"], b"")

        # ---- client side
        crecords = _handshake_records(client_payload)
        ch_body = _first(crecords, 1)
        if ch_body is not None:
            try:
                hello = tlsmod.parse_client_hello(ch_body)
            except Exception:
                hello = None
            if hello:
                rec["sni"] = hello.get("sni")
                if hello.get("ech"):
                    # The fingerprint describes the outer hello; the real one is
                    # encrypted. Mark it so the rules can say so.
                    rec["ech"] = True
                alpn = hello.get("alpn") or []
                if alpn:
                    rec["alpn"] = alpn[0].decode("ascii", "replace") if isinstance(alpn[0], bytes) else str(alpn[0])
                try:
                    rec["fingerprints"]["ja3"] = ja3mod.ja3(hello)
                except Exception:
                    pass
                try:
                    rec["fingerprints"]["ja4"] = ja4mod.ja4(hello)
                except Exception:
                    pass

        # ---- server side
        srecords = _handshake_records(server_payload)
        sh_body = _first(srecords, 2)
        if sh_body is not None:
            try:
                shello = tlsmod.parse_server_hello(sh_body)
            except Exception:
                shello = None
            if shello:
                try:
                    rec["fingerprints"]["ja3s"] = ja3mod.ja3s(shello)
                except Exception:
                    pass
                try:
                    rec["fingerprints"]["ja4s"] = ja4mod.ja4s(shello)
                except Exception:
                    pass

        cert_body = _first(srecords, 11)
        if cert_body is not None:
            try:
                certs = tlsmod.parse_certificate_message(cert_body)
                if certs:
                    rec["fingerprints"]["ja4x"] = ja4mod.ja4x(certs[0])
            except Exception:
                pass

        # ---- HTTP on the client stream (plaintext only; TLS payloads raise)
        req = rec.pop("http", None)
        if req is None:
            try:
                req = tlsmod.parse_http_request(client_payload)
            except Exception:
                req = None
        if req:
            try:
                rec["fingerprints"]["ja4h"] = ja4mod.ja4h(req)
            except Exception:
                pass
            for name, value in (req.get("headers") or []):
                if name.lower() == "user-agent":
                    rec["user_agent"] = value
                    break

        # ---- TCP SYN from the client
        syn = syns.get(rec["client"])
        if syn is not None:
            try:
                rec["fingerprints"]["ja4t"] = ja4mod.ja4t(tlsmod.parse_tcp_syn(syn))
            except Exception:
                pass

        # ---- timestamp: the first packet of the flow
        stamps = [p.get("ts") for p in packets
                  if p.get("src_ip") == rec["client"][0] and p.get("src_port") == rec["client"][1]]
        rec["ts"] = min([s for s in stamps if isinstance(s, (int, float))], default=0.0)
        results.append(rec)
    return results


def quic_events(packets, corpus=None):
    """One event per QUIC Initial packet we can decrypt and fingerprint.

    QUIC is TLS over UDP. Its Initial packets are encrypted, but with keys
    derived from a public salt and the connection ID, so a passive reader can
    decrypt them -- which is the only way to fingerprint HTTP/3 at all.
    """
    if quic is None or not getattr(quic, "HAVE_CRYPTO", False):
        return []
    out = []
    # A QUIC ClientHello is spread over several Initial packets, so the frames
    # are reassembled per connection rather than read from one datagram.
    assembler = quic.CryptoAssembler()
    for packet in packets:
        if packet.get("protocol") != "udp":
            continue
        payload = packet.get("payload") or b""
        if not payload:
            continue
        try:
            found = assembler.feed(payload)
        except Exception:
            found = None
        if not found:
            continue
        try:
            hello = tlsmod.parse_client_hello(found["client_hello"])
        except Exception:
            continue
        if not hello:
            continue
        fingerprints = {}
        for kind, fn in (("ja3", ja3mod.ja3), ("ja4", ja4mod.ja4)):
            try:
                fingerprints[kind] = fn(hello, proto="q")
            except TypeError:
                try:
                    fingerprints[kind] = fn(hello)
                except Exception:
                    pass
            except Exception:
                pass
        if not fingerprints:
            continue
        alpn = hello.get("alpn") or []
        event = {
            "ts": packet.get("ts") or 0.0,
            "src_ip": packet.get("src_ip"), "src_port": packet.get("src_port"),
            "dst_ip": packet.get("dst_ip"), "dst_port": packet.get("dst_port"),
            "sni": hello.get("sni"),
            "alpn": (alpn[0].decode("ascii", "replace")
                     if alpn and isinstance(alpn[0], bytes) else (alpn[0] if alpn else None)),
            "user_agent": None,
            "fingerprints": fingerprints,
            "transport": "quic",
            "quic_version": found.get("version"),
        }
        if hello.get("ech"):
            event["ech"] = True
        _attach_intel(event, corpus)
        out.append(event)
    return out


def _attach_intel(event, corpus):
    """Label an event with the first corpus match among its fingerprints."""
    if corpus is None:
        return event
    for kind, value in (event.get("fingerprints") or {}).items():
        try:
            entry = corpus.match(kind, value)
        except Exception:
            entry = None
        if entry is not None:
            event["category"] = getattr(entry, "category", None)
            event["intel_name"] = getattr(entry, "name", None)
            break
    return event


def events_from_pcap(path, corpus=None):
    """Read a capture and return one event per fingerprinted TLS flow."""
    packets = pcapmod.read_pcap(path)
    events = list(quic_events(packets, corpus))
    for rec in fingerprint_streams(packets):
        client = rec["client"] or ("", 0)
        server = rec["server"] or ("", 0)
        event = {
            "ts": rec["ts"] or 0.0,
            "src_ip": client[0],
            "src_port": client[1],
            "dst_ip": server[0],
            "dst_port": server[1],
            "sni": rec["sni"],
            "alpn": rec["alpn"],
            "user_agent": rec["user_agent"],
            "fingerprints": dict(rec["fingerprints"]),
            "transport": "tcp",
        }
        if rec.get("ech"):
            event["ech"] = True
        _attach_intel(event, corpus)
        events.append(event)
    return events


def analyse(path, store, corpus, rules_module=None):
    """Fingerprint a capture, run the rules and persist everything."""
    if rules_module is None:
        from . import rules as rules_module
    from .app import os_by_ja3

    events = events_from_pcap(path, corpus)
    ctx = {
        "store": store,
        "corpus": corpus,
        "seen_before": store.seen_before,
        "os_by_ja3": os_by_ja3(corpus),
    }
    alerts = []
    for event in events:
        try:
            produced = rules_module.evaluate(event, ctx) or []
        except Exception:
            produced = []
        store.add_event(event)
        for alert in produced:
            alert = dict(alert)
            alert.setdefault("src_ip", event.get("src_ip"))
            alert.setdefault("sni", event.get("sni"))
            alert.setdefault("ts", event.get("ts"))
            store.add_alert(alert)
            alerts.append(alert)
    return events, alerts
