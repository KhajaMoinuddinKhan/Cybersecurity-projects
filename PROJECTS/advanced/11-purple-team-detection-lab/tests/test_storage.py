from datetime import datetime, timezone
from pathlib import Path

from src.models import Alert
from src.storage import alert_stats, list_alerts, replace_alerts


def make_alert(title="Demo alert"):
    now = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
    return Alert(
        rule_id="DET-001",
        title=title,
        description="demo",
        severity="High",
        technique_id="T1110",
        technique_name="Brute Force",
        first_seen=now,
        last_seen=now,
        group_value="198.51.100.23",
        event_ids=("EVT-1",),
        host="vpn-gateway",
        user="admin",
        source="198.51.100.23",
    )


def test_storage_filters_and_stats(tmp_path: Path):
    db = tmp_path / "alerts.db"
    replace_alerts(db, [make_alert()])
    assert alert_stats(db)["high"] == 1
    assert len(list_alerts(db, severity="High")) == 1
    assert len(list_alerts(db, search="vpn")) == 1
    assert list_alerts(db, search="%") == []
