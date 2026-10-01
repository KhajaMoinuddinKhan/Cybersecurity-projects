"""Detection and correlation logic."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from .models import Alert, DetectionRule, SecurityEvent


def _matches_condition(event: SecurityEvent, condition: dict[str, Any]) -> bool:
    actual = event.field(str(condition["field"]))
    expected = condition["value"]
    operator = condition["operator"]

    if operator == "equals":
        return str(actual).lower() == str(expected).lower()
    if operator == "contains":
        return str(expected).lower() in str(actual or "").lower()
    if operator == "in":
        if not isinstance(expected, list):
            return False
        return str(actual).lower() in {str(value).lower() for value in expected}
    if operator == "greater_or_equal":
        try:
            return float(actual) >= float(expected)
        except (TypeError, ValueError):
            return False
    return False


def event_matches(event: SecurityEvent, rule: DetectionRule) -> bool:
    return all(_matches_condition(event, condition) for condition in rule.conditions)


def _alert_from_events(rule: DetectionRule, events: list[SecurityEvent], group: str) -> Alert:
    first = events[0]
    last = events[-1]
    return Alert(
        rule_id=rule.rule_id,
        title=rule.title,
        description=rule.description,
        severity=rule.severity,
        technique_id=rule.technique_id,
        technique_name=rule.technique_name,
        first_seen=first.timestamp,
        last_seen=last.timestamp,
        group_value=group,
        event_ids=tuple(event.event_id for event in events),
        host=last.host,
        user=last.user,
        source=last.source,
    )


def _run_match_rule(events: list[SecurityEvent], rule: DetectionRule) -> list[Alert]:
    alerts = []
    for event in events:
        if event_matches(event, rule):
            group = str(event.field(rule.group_by)) if rule.group_by else event.event_id
            alerts.append(_alert_from_events(rule, [event], group))
    return alerts


def _run_threshold_rule(events: list[SecurityEvent], rule: DetectionRule) -> list[Alert]:
    assert rule.group_by is not None
    assert rule.threshold is not None
    assert rule.window_minutes is not None

    matching = [event for event in events if event_matches(event, rule)]
    grouped: dict[str, list[SecurityEvent]] = defaultdict(list)
    for event in matching:
        grouped[str(event.field(rule.group_by) or "unknown")].append(event)

    alerts: list[Alert] = []
    window = timedelta(minutes=rule.window_minutes)

    for group, group_events in grouped.items():
        group_events.sort(key=lambda event: event.timestamp)
        start = 0
        last_alert_end = -1

        for end, event in enumerate(group_events):
            while event.timestamp - group_events[start].timestamp > window:
                start += 1

            if end - start + 1 >= rule.threshold and end > last_alert_end:
                matched = group_events[start : end + 1]
                alerts.append(_alert_from_events(rule, matched, group))
                last_alert_end = end
                start = end + 1

    return alerts


def run_detection(events: list[SecurityEvent], rules: list[DetectionRule]) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in rules:
        if rule.rule_type == "match":
            alerts.extend(_run_match_rule(events, rule))
        else:
            alerts.extend(_run_threshold_rule(events, rule))

    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    return sorted(
        alerts,
        key=lambda alert: (severity_order.get(alert.severity, 9), alert.first_seen, alert.rule_id),
    )
