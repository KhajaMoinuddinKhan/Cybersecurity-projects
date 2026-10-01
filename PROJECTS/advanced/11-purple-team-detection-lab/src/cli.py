"""Command-line entry point for the lab."""
from __future__ import annotations

import argparse
from pathlib import Path

from .dashboard import serve
from .engine import run_detection
from .event_io import load_events, load_rules
from .storage import alert_stats, replace_alerts


def _default_path(relative: str) -> Path:
    return Path(__file__).resolve().parent.parent / relative


def command_detect(args: argparse.Namespace) -> None:
    events = load_events(args.events)
    rules = load_rules(args.rules)
    alerts = run_detection(events, rules)
    replace_alerts(args.db, alerts)

    print(f"Events loaded: {len(events)}")
    print(f"Rules loaded: {len(rules)}")
    print(f"Alerts created: {len(alerts)}")
    for alert in alerts:
        print(
            f"[{alert.severity}] {alert.rule_id} | {alert.title} | "
            f"{alert.technique_id} | {alert.group_value} | events={len(alert.event_ids)}"
        )


def command_summary(args: argparse.Namespace) -> None:
    stats = alert_stats(args.db)
    print(f"Total alerts: {stats['total']}")
    print(f"High: {stats['high']}")
    print(f"Medium: {stats['medium']}")
    print(f"Low: {stats['low']}")
    print("ATT&CK techniques:")
    for item in stats["techniques"]:
        print(f"  {item['technique_id']} {item['technique_name']}: {item['count']}")


def command_serve(args: argparse.Namespace) -> None:
    serve(args.db, args.host, args.port)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Purple Team Detection Lab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    detect = subparsers.add_parser("detect", help="Run rules against an event file")
    detect.add_argument("--events", type=Path, default=_default_path("data/sample_events.json"))
    detect.add_argument("--rules", type=Path, default=_default_path("rules/detection_rules.json"))
    detect.add_argument("--db", type=Path, default=Path("purple_lab.db"))
    detect.set_defaults(func=command_detect)

    summary = subparsers.add_parser("summary", help="Print alert totals")
    summary.add_argument("--db", type=Path, default=Path("purple_lab.db"))
    summary.set_defaults(func=command_summary)

    dashboard = subparsers.add_parser("serve", help="Start the local analyst dashboard")
    dashboard.add_argument("--db", type=Path, default=Path("purple_lab.db"))
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8080)
    dashboard.set_defaults(func=command_serve)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
