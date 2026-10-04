"""Command line entry point.

    python -m src.cli analyse <capture.pcap> [--db console.db]
    python -m src.cli serve   [--db console.db] [--port 5001]
    python -m src.cli demo    [--db console.db]
"""
from __future__ import annotations

import argparse
import os
import sys


def _default_db():
    return os.path.join(os.getcwd(), "tls_console.db")


def _corpus():
    from .corpus import load_corpus
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return load_corpus(os.path.join(here, "data", "corpus"))


def cmd_analyse(args):
    from .pipeline import analyse
    from .store import Store
    store = Store(args.db)
    corpus = _corpus()
    events, alerts = analyse(args.capture, store, corpus)
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
    from .store import Store
    store = Store(args.db)
    app = create_app(store, _corpus())
    print("console on http://127.0.0.1:%d  (db %s)" % (args.port, args.db))
    app.run(host="127.0.0.1", port=args.port, debug=False)
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
        ("analyse", cmd_analyse, "fingerprint a capture file"),
        ("serve", cmd_serve, "run the console"),
        ("demo", cmd_demo, "fingerprint a built-in synthetic capture"),
    ):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("--db", default=_default_db())
        if name == "analyse":
            sp.add_argument("capture")
        if name == "serve":
            sp.add_argument("--port", type=int, default=5001)
        sp.set_defaults(func=fn)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
