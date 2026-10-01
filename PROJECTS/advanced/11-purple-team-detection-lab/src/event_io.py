"""Load event and rule files."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import DetectionRule, SecurityEvent


VALID_SEVERITIES = {"High", "Medium", "Low"}
VALID_RULE_TYPES = {"match", "threshold"}
VALID_OPERATORS = {"equals", "contains", "in", "greater_or_equal"}


def load_events(path: Path) -> list[SecurityEvent]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("Event file must contain a JSON list")
    if not all(isinstance(item, dict) for item in raw):
        raise ValueError("Every event must be a JSON object")

    events = [SecurityEvent.from_dict(item) for item in raw]
    ids = [event.event_id for event in events]
    if len(ids) != len(set(ids)):
        raise ValueError("Event IDs must be unique")
    return sorted(events, key=lambda event: event.timestamp)


def _validate_condition(condition: dict[str, Any], rule_id: str) -> None:
    field = condition.get("field")
    operator = condition.get("operator")
    if not isinstance(field, str) or not field.strip():
        raise ValueError(f"Rule {rule_id} has a condition without a field")
    if operator not in VALID_OPERATORS:
        raise ValueError(f"Rule {rule_id} uses unsupported operator: {operator!r}")
    if "value" not in condition:
        raise ValueError(f"Rule {rule_id} condition is missing a value")


def load_rules(path: Path) -> list[DetectionRule]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("Rules file must contain a JSON list")

    rules: list[DetectionRule] = []
    seen_ids: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("Every rule must be a JSON object")

        rule_id = str(item.get("rule_id", "")).strip()
        if not rule_id:
            raise ValueError("Rule ID cannot be empty")
        if rule_id in seen_ids:
            raise ValueError(f"Duplicate rule ID: {rule_id}")
        seen_ids.add(rule_id)

        severity = str(item.get("severity", "")).title()
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"Rule {rule_id} has unsupported severity: {severity}")

        rule_type = str(item.get("type", "")).lower()
        if rule_type not in VALID_RULE_TYPES:
            raise ValueError(f"Rule {rule_id} has unsupported type: {rule_type}")

        conditions = item.get("conditions", [])
        if not isinstance(conditions, list) or not conditions:
            raise ValueError(f"Rule {rule_id} must contain at least one condition")
        for condition in conditions:
            if not isinstance(condition, dict):
                raise ValueError(f"Rule {rule_id} has an invalid condition")
            _validate_condition(condition, rule_id)

        group_by = item.get("group_by")
        threshold = item.get("threshold")
        window_minutes = item.get("window_minutes")
        if rule_type == "threshold":
            if not isinstance(group_by, str) or not group_by:
                raise ValueError(f"Threshold rule {rule_id} needs group_by")
            if not isinstance(threshold, int) or threshold < 2:
                raise ValueError(f"Threshold rule {rule_id} needs threshold >= 2")
            if not isinstance(window_minutes, int) or window_minutes < 1:
                raise ValueError(f"Threshold rule {rule_id} needs window_minutes >= 1")

        rules.append(
            DetectionRule(
                rule_id=rule_id,
                title=str(item.get("title", rule_id)),
                description=str(item.get("description", "")),
                severity=severity,
                technique_id=str(item.get("technique_id", "Unmapped")),
                technique_name=str(item.get("technique_name", "Unmapped")),
                rule_type=rule_type,
                conditions=tuple(conditions),
                group_by=str(group_by) if group_by else None,
                threshold=threshold if isinstance(threshold, int) else None,
                window_minutes=window_minutes if isinstance(window_minutes, int) else None,
            )
        )

    return rules
