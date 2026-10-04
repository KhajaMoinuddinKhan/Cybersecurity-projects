"""A live feed: the newest handshakes, pushed to whoever is watching.

The console used to be a view of a store, refreshed by a poll. That is enough
to read a capture that has already been analysed, and useless for watching
traffic: by the time a two-second poll fires, the handshake it would have shown
you is one row among many.

This module holds the two pieces a feed needs. LiveFeed is a bounded ring of
recent events and alerts with subscribers that are pushed each new item, so a
browser can be handed a stream rather than asking again every few seconds.
CaptureSession owns the capture thread and the sensor, so the server can watch
an interface itself instead of relying on a separate command that stops when
its duration runs out.
"""
from __future__ import annotations

import collections
import queue
import threading
import time


class LiveFeed:
    """Recent events and alerts, with push subscribers.

    Bounded on purpose. A feed is what is happening now, not an archive; the
    store is the archive, and it already holds everything.
    """

    def __init__(self, maxlen=500):
        self._lock = threading.Lock()
        self._events = collections.deque(maxlen=maxlen)
        self._alerts = collections.deque(maxlen=maxlen)
        self._subscribers = []
        self._sequence = 0
        self.totals = {"events": 0, "alerts": 0, "since": time.time()}

    # ------------------------------------------------------------- publishing

    def publish_event(self, event):
        self._publish("event", event)

    def publish_alert(self, alert):
        self._publish("alert", alert)

    def _publish(self, kind, item):
        if not isinstance(item, dict):
            return
        with self._lock:
            self._sequence += 1
            record = {"seq": self._sequence, "kind": kind, "at": time.time(), "item": item}
            (self._events if kind == "event" else self._alerts).append(record)
            self.totals["events" if kind == "event" else "alerts"] += 1
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(record)
            except queue.Full:
                # A subscriber that cannot keep up loses records rather than
                # blocking the capture thread. The store still has them all.
                pass

    # ------------------------------------------------------------ subscribing

    def subscribe(self, maxsize=1000):
        """Return a queue that receives every record published from now on."""
        q = queue.Queue(maxsize=maxsize)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    @property
    def subscriber_count(self):
        with self._lock:
            return len(self._subscribers)

    # -------------------------------------------------------------- reading

    def recent(self, limit=100, kind=None):
        with self._lock:
            events = list(self._events)
            alerts = list(self._alerts)
        if kind == "event":
            return events[-limit:]
        if kind == "alert":
            return alerts[-limit:]
        merged = events + alerts
        merged.sort(key=lambda r: r["seq"])
        return merged[-limit:]

    def stats(self):
        with self._lock:
            events = len(self._events)
            alerts = len(self._alerts)
        elapsed = max(time.time() - self.totals["since"], 1e-6)
        return {
            "events_total": self.totals["events"],
            "alerts_total": self.totals["alerts"],
            "events_held": events,
            "alerts_held": alerts,
            "subscribers": self.subscriber_count,
            "events_per_minute": round(self.totals["events"] * 60.0 / elapsed, 1),
            "uptime_seconds": round(elapsed, 1),
        }


class CaptureSession:
    """Owns the capture thread: start it, stop it, ask it how it is doing.

    One session per server. Starting when one is already running is refused
    rather than silently doing nothing, because two capture threads writing the
    same store would double every event.
    """

    def __init__(self, store, corpus, feed, interface=None, bpf=None):
        self.store = store
        self.corpus = corpus
        self.feed = feed
        self.interface = interface
        self.bpf = bpf
        self._thread = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.started_at = None
        self.error = None
        self.interface_used = None
        self.sensor = None

    # ------------------------------------------------------------- lifecycle

    def start(self):
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False, "a capture is already running"
            from . import capture as capture_mod
            if not capture_mod.available():
                return False, ("no capture driver found; install Npcap "
                               "(https://npcap.com/) to capture live traffic")
            try:
                iface = capture_mod.pick_interface(self.interface)
            except capture_mod.CaptureUnavailable as exc:
                return False, str(exc)
            self._stop.clear()
            self.error = None
            self.interface_used = iface
            self.started_at = time.time()
            self._thread = threading.Thread(target=self._run, args=(iface,), daemon=True)
            self._thread.start()
            return True, "capture started on %s" % iface["description"]

    def stop(self, timeout=5.0):
        with self._lock:
            thread = self._thread
            if thread is None or not thread.is_alive():
                self._thread = None
                return False, "no capture is running"
            self._stop.set()
        thread.join(timeout=timeout)
        with self._lock:
            self._thread = None
        return True, "capture stopped"

    def _run(self, iface):
        from . import capture as capture_mod
        from .live import LiveSensor
        sensor = None
        try:
            bpf = self.bpf or capture_mod.DEFAULT_FILTER
            with capture_mod.LiveCapture(iface["name"], bpf=bpf) as cap:
                sensor = LiveSensor(
                    self.store, self.corpus,
                    on_event=self.feed.publish_event,
                    on_alert=self.feed.publish_alert,
                )
                self.sensor = sensor
                last_tick = 0.0
                for packet in cap.packets():
                    if self._stop.is_set():
                        break
                    sensor.feed(packet)
                    now = time.time()
                    if now - last_tick >= 0.5:
                        sensor.tick()
                        last_tick = now
        except Exception as exc:                      # noqa: BLE001 - reported, not raised
            self.error = "%s: %s" % (type(exc).__name__, exc)
        finally:
            if sensor is not None:
                try:
                    sensor.flush()
                except Exception:
                    pass
            self.sensor = sensor

    # --------------------------------------------------------------- status

    def status(self):
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
        out = {
            "running": running,
            "interface": (self.interface_used or {}).get("description"),
            "interface_index": (self.interface_used or {}).get("index"),
            "filter": self.bpf,
            "started_at": self.started_at,
            "error": self.error,
        }
        if running and self.started_at:
            out["uptime_seconds"] = round(time.time() - self.started_at, 1)
        if self.sensor is not None:
            s = self.sensor.stats()
            out.update({"packets": s["packets"], "flows": s["flows"],
                        "events": s["events"], "alerts": s["alerts"],
                        "in_flight": s["in_flight"]})
            elapsed = max(time.time() - (self.started_at or time.time()), 1e-6)
            out["packets_per_second"] = round(s["packets"] / elapsed, 1)
        return out
