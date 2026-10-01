import json
from pathlib import Path

import pytest

from src.event_io import load_events, load_rules


def test_duplicate_event_ids_are_rejected(tmp_path: Path):
    path = tmp_path / "events.json"
    event = {"event_id":"1","timestamp":"2026-10-01T09:00:00+00:00","event_type":"x","source":"s","user":"u","host":"h","data":{}}
    path.write_text(json.dumps([event, event]), encoding="utf-8")
    with pytest.raises(ValueError, match="unique"):
        load_events(path)


def test_repository_rules_load():
    path = Path(__file__).resolve().parents[1] / "rules" / "detection_rules.json"
    rules = load_rules(path)
    assert len(rules) == 5
    assert {rule.rule_id for rule in rules} == {"DET-001","DET-002","DET-003","DET-004","DET-005"}


@pytest.mark.parametrize("operator,value", [("in", "text"), ("in", []), ("greater_or_equal", "no"), ("greater_or_equal", True), ("greater_or_equal", "nan")])
def test_invalid_condition_values_are_rejected(tmp_path, operator, value):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps([dict(rule_id="R", severity="High", type="match", conditions=[dict(field="x", operator=operator, value=value)])]))
    with pytest.raises(ValueError):
        load_rules(path)
