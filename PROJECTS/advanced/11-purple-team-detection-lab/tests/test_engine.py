from datetime import datetime, timezone

from src.engine import run_detection
from src.models import DetectionRule, SecurityEvent


def event(event_id, minute, event_type="auth_failure", source="198.51.100.10", **data):
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime(2026, 10, 1, 9, minute, tzinfo=timezone.utc),
        event_type=event_type,
        source=source,
        user="admin",
        host="lab-host",
        data=data,
    )


def test_threshold_rule_correlates_events_in_window():
    rule = DetectionRule(
        rule_id="DET-X",
        title="Repeated failures",
        description="demo",
        severity="High",
        technique_id="T1110",
        technique_name="Brute Force",
        rule_type="threshold",
        conditions=({"field":"event_type","operator":"equals","value":"auth_failure"},),
        group_by="source",
        threshold=3,
        window_minutes=5,
    )
    alerts = run_detection([event("1",0), event("2",1), event("3",3)], [rule])
    assert len(alerts) == 1
    assert alerts[0].event_ids == ("1", "2", "3")


def test_match_rule_reads_fields_from_event_data():
    rule = DetectionRule(
        rule_id="DET-Y",
        title="Large transfer",
        description="demo",
        severity="Medium",
        technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel",
        rule_type="match",
        conditions=(
            {"field":"event_type","operator":"equals","value":"network_connection"},
            {"field":"bytes_out","operator":"greater_or_equal","value":50000000},
        ),
    )
    alerts = run_detection([event("1",0,event_type="network_connection",bytes_out=60000000)], [rule])
    assert len(alerts) == 1
