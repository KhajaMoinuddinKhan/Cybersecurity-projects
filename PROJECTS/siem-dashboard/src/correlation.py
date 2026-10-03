"""Correlation: fire on a sequence of alerts, not on a single event.

A single-event rule can say "an encoded PowerShell command ran". It cannot say
"and then that same host opened a connection to somewhere new". That second
statement is where most of the real signal lives, and it is what this module
adds.

The engine reads alerts that are already stored, groups them by host, user or
address, and looks for the ordered sequence each correlation rule describes
inside its time window. The result is a new alert that names the events it was
built from, so a reader can check the reasoning instead of trusting it.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .rules import CorrelationRule

CORRELATION_SOURCE = "correlation"


def _parse(timestamp: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _seconds_between(start: str, end: str) -> float | None:
    first, second = _parse(start), _parse(end)
    if first is None or second is None:
        return None
    return (second - first).total_seconds()


def _find_sequence(
    events: list[dict[str, Any]],
    steps: tuple[str, ...],
    needed: int,
    window_seconds: int,
) -> list[dict[str, Any]] | None:
    """Find the earliest ordered run of ``needed`` steps inside the window.

    Events must already be in ascending time order. Only the first ``needed``
    steps are required, which is how a rule expresses "three failed logons and
    then a lockout" without listing every permutation.
    """

    wanted = list(steps[:needed])
    for start in range(len(events)):
        cursor = 0
        matched: list[dict[str, Any]] = []
        for event in events[start:]:
            if str(event.get("rule_id") or "") == wanted[cursor]:
                matched.append(event)
                cursor += 1
                if cursor == len(wanted):
                    break
        if cursor == len(wanted):
            span = _seconds_between(matched[0]["timestamp"], matched[-1]["timestamp"])
            if span is not None and span <= window_seconds:
                return matched
    return None


def _describe(rule: CorrelationRule, matched: list[dict[str, Any]], group: str) -> str:
    parts = [
        f"{event.get('rule_name') or event.get('rule_id')} at {event['timestamp']}"
        for event in matched
    ]
    span = _seconds_between(matched[0]["timestamp"], matched[-1]["timestamp"]) or 0
    return (
        f"{rule.title}: {rule.group_by} {group} produced "
        + ", then ".join(parts)
        + f" within {int(span)}s (window {rule.window_seconds}s)."
    )


def build_correlation_payloads(
    events: Iterable[dict[str, Any]],
    rules: Iterable[CorrelationRule],
) -> list[dict[str, Any]]:
    """Turn stored alerts into correlation alerts.

    ``events`` are rows with ``rule_id``, ``timestamp`` and the grouping field.
    Nothing is written here; the caller decides whether to store the result.
    """

    ordered = sorted(
        (event for event in events if event.get("rule_id")),
        key=lambda item: (str(item.get("timestamp") or ""), int(item.get("id") or 0)),
    )

    payloads: list[dict[str, Any]] = []
    for rule in rules:
        groups: dict[str, list[dict[str, Any]]] = {}
        for event in ordered:
            key = str(event.get(rule.group_by) or "").strip()
            if key and key != "unknown":
                groups.setdefault(key, []).append(event)

        for group, members in groups.items():
            matched = _find_sequence(members, rule.steps, rule.min_steps, rule.window_seconds)
            if not matched:
                continue

            first, last = matched[0], matched[-1]
            payloads.append(
                {
                    "timestamp": last["timestamp"],
                    "channel": "correlation",
                    "provider": "rule-engine",
                    "event_id": rule.id,
                    "level": "Information",
                    "severity": rule.level,
                    "username": str(first.get("username") or "unknown"),
                    "host": str(first.get("host") or "unknown"),
                    "source_ip": str(first.get("source_ip") or "local"),
                    "message": _describe(rule, matched, group),
                    "record_id": "",
                    "source": CORRELATION_SOURCE,
                    "is_alert": True,
                    "rule_name": rule.title,
                    "rule_id": rule.id,
                    "techniques": ",".join(rule.techniques),
                    "external_id": f"corr:{rule.id}:{group}:{first.get('id')}",
                    "raw_log": json.dumps(
                        {
                            "correlation_rule": rule.id,
                            "group_by": rule.group_by,
                            "group": group,
                            "window_seconds": rule.window_seconds,
                            "contributing_events": [
                                {
                                    "id": event.get("id"),
                                    "rule_id": event.get("rule_id"),
                                    "rule_name": event.get("rule_name"),
                                    "timestamp": event.get("timestamp"),
                                    "event_id": event.get("event_id"),
                                    "channel": event.get("channel"),
                                }
                                for event in matched
                            ],
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    "matched_on": [str(event.get("rule_id") or "") for event in matched],
                    "fields": {
                        "correlation_rule": rule.id,
                        "group": group,
                        "steps_matched": str(len(matched)),
                    },
                }
            )

    return payloads


def correlate(db_path: Path, rules: Iterable[CorrelationRule], *, since_minutes: int = 120) -> int:
    """Run every correlation rule over recent alerts and store what fires.

    Returns the number of new correlation alerts. Re-running is safe: each
    correlation alert carries a deterministic external id, so the store's
    unique index absorbs a repeat.
    """

    from .app import ingest_payloads, query_events

    rules = list(rules)
    if not rules:
        return 0

    events = query_events(
        db_path,
        since_minutes=since_minutes,
        alerts_only=True,
        limit=2000,
    )
    payloads = build_correlation_payloads(events, rules)
    if not payloads:
        return 0
    return ingest_payloads(db_path, payloads, CORRELATION_SOURCE)
