"""Command line entry point.

    python -m src.cli interfaces                      list capturable interfaces
    python -m src.cli analyse <capture.pcap> [--db console.db]
    python -m src.cli demo    [--db console.db]
    python -m src.cli watch   [--interface N] [--filter EXPR] [--db console.db]
    python -m src.cli serve   [--db console.db] [--port 5001]
"""
from __future__ import annotations

import argparse
import os
import sys
import time


def _default_db():
    return os.path.join(os.getcwd(), "tls_console.db")


def _clock(ts):
    """A short local time for a packet timestamp, falling back to the raw value."""
    if not isinstance(ts, (int, float)):
        return "--:--:--"
    try:
        return time.strftime("%H:%M:%S", time.localtime(ts))
    except Exception:
        return str(ts)


def _corpus():
    from .corpus import load_corpus
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return load_corpus(os.path.join(here, "data", "corpus"))


def cmd_analyse(args):
    from .pipeline import analyse
    from .store import Store
    store = Store(args.db)
    corpus = _corpus()
    try:
        events, alerts = analyse(args.capture, store, corpus)
    except (OSError, ValueError) as exc:
        # A capture that cannot be read is an answer, not a crash: the reader
        # raises ValueError with a sentence in it, and a traceback would bury
        # that sentence under six frames of our own code.
        store.close()
        print("could not read %s: %s" % (args.capture, exc), file=sys.stderr)
        return 1
    print("read      : %s" % args.capture)
    print("events    : %d" % len(events))
    print("alerts    : %d" % len(alerts))
    for a in alerts:
        print("  [%-8s] %-14s %s" % (a.get("severity"), a.get("rule"), a.get("title")))
    print("fingerprints: %d" % store.stats().get("fingerprints", 0))
    store.close()
    return 0


def cmd_serve(args):
    from .app import create_app
    from .feed import CaptureSession, LiveFeed
    from .store import Store

    store = Store(args.db)
    corpus = _corpus()
    feed = LiveFeed()
    session = CaptureSession(store, corpus, feed,
                             interface=args.interface, bpf=args.filter)
    app = create_app(store, corpus, feed=feed, session=session)

    if args.capture:
        ok, message = session.start()
        print("capture   : %s" % message)
        if not ok:
            print("            (the console still runs; start capture from the Live view)")

    print("console on http://127.0.0.1:%d  (db %s)" % (args.port, args.db))
    print("live feed : /api/stream   capture control: /api/capture/start")
    # threaded so the event-stream endpoint can hold a connection open while the
    # capture thread keeps publishing and other requests are still served
    app.run(host="127.0.0.1", port=args.port, debug=False, threaded=True)
    try:
        session.stop()
    except Exception:
        pass
    store.close()
    return 0


def cmd_interfaces(args):
    """List what this machine can capture from, and say whether capture is possible at all."""
    from . import capture
    print("capture driver :", "available" if capture.available() else "NOT FOUND")
    if not capture.available():
        print("  Live capture needs a capture driver -- Npcap on Windows -- and normally")
        print("  an elevated shell. The file and ingest paths work without either.")
        return 1
    print("default filter :", capture.DEFAULT_FILTER)
    print()
    print("%-5s %-58s %s" % ("IDX", "DESCRIPTION", "DEVICE"))
    for i in capture.list_interfaces():
        print("%-5d %-58s %s" % (i["index"], i["description"][:58], i["name"]))
    print()
    try:
        chosen = capture.pick_interface(None)
        print("would pick by default: [%d] %s" % (chosen["index"], chosen["description"]))
    except Exception as exc:
        print("no default interface:", exc)
    return 0


def cmd_watch(args):
    """Capture live, fingerprint each handshake as it arrives, and report as it goes."""
    from . import capture
    from .live import LiveSensor
    from .store import Store

    if not capture.available():
        print("No capture driver found, so there is no interface to open.")
        print("Live capture needs a capture driver -- Npcap on Windows -- and normally")
        print("an elevated shell. The file and ingest paths work without either.")
        return 1

    try:
        iface = capture.pick_interface(args.interface)
    except capture.CaptureUnavailable as exc:
        print("interface error:", exc)
        return 1
    print("interface : [%d] %s" % (iface["index"], iface["description"]))
    print("filter    : %s" % (args.filter or capture.DEFAULT_FILTER))
    print("db        : %s" % args.db)
    print("stop with Ctrl-C%s" % ("" if not args.duration else " (or after %gs)" % args.duration))
    print()

    store = Store(args.db)
    corpus = _corpus()

    def show_event(event):
        fp = event.get("fingerprints") or {}
        print("%s  %s:%s -> %s:%s  %s" % (
            _clock(event.get("ts")),
            event.get("src_ip"), event.get("src_port"),
            event.get("dst_ip"), event.get("dst_port"),
            event.get("sni") or "(no SNI)"))
        for kind in sorted(fp):
            print("        %-6s %s" % (kind, fp[kind]))
        if event.get("intel_name"):
            print("        intel  %s (%s)" % (event["intel_name"], event.get("category")))

    def show_alert(alert):
        print("    ! [%-8s] %-14s %s" % (alert.get("severity"), alert.get("rule"),
                                         alert.get("title")))

    sensor = LiveSensor(store, corpus, on_event=show_event, on_alert=show_alert)
    started = time.time()
    try:
        with capture.LiveCapture(iface["name"], bpf=args.filter or capture.DEFAULT_FILTER) as cap:
            last_tick = 0.0
            for packet in cap.packets():
                sensor.feed(packet)
                now = time.time()
                if now - last_tick >= 0.5:
                    sensor.tick()
                    last_tick = now
                if args.duration and (now - started) >= args.duration:
                    break
    except KeyboardInterrupt:
        print("\nstopping...")
    except capture.CaptureUnavailable as exc:
        print("capture error:", exc)
        store.close()
        return 1

    for item in sensor.flush():
        if "fingerprints" in item:
            show_event(item)
    stats = sensor.stats()
    print()
    print("packets %d | flows %d | events %d | alerts %d | in flight %d"
          % (stats["packets"], stats["flows"], stats["events"], stats["alerts"], stats["in_flight"]))
    store.close()
    return 0


def cmd_demo(args):
    """Analyse the built-in synthetic capture so the console has something to show."""
    import tempfile
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from fixtures.make_pcap import make_classic_pcap
    from .pipeline import analyse
    from .store import Store
    path = make_classic_pcap()
    store = Store(args.db)
    events, alerts = analyse(path, store, _corpus())
    print("demo capture : %s" % path)
    print("events       : %d" % len(events))
    print("alerts       : %d" % len(alerts))
    for a in alerts:
        print("  [%-8s] %-14s %s" % (a.get("severity"), a.get("rule"), a.get("title")))
    store.close()
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="tls-fingerprint-console")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn, helptext in (
        ("interfaces", cmd_interfaces, "list capturable interfaces"),
        ("analyse", cmd_analyse, "fingerprint a capture file"),
        ("demo", cmd_demo, "fingerprint a built-in synthetic capture"),
        ("watch", cmd_watch, "capture live and fingerprint handshakes as they arrive"),
        ("serve", cmd_serve, "run the console"),
    ):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("--db", default=_default_db())
        if name == "analyse":
            sp.add_argument("capture")
        if name == "watch":
            sp.add_argument("--interface", default=None,
                            help="interface index or part of its description")
            sp.add_argument("--filter", default=None, help="a BPF filter expression")
            sp.add_argument("--duration", type=float, default=None,
                            help="stop after this many seconds")
        if name == "serve":
            sp.add_argument("--port", type=int, default=5001)
            sp.add_argument("--capture", action="store_true",
                            help="start capturing from a live interface immediately")
            sp.add_argument("--interface", default=None,
                            help="interface index or part of its description")
            sp.add_argument("--filter", default=None, help="a BPF filter expression")
        sp.set_defaults(func=fn)
    args = p.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print("%s failed: %s" % (args.cmd, exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
