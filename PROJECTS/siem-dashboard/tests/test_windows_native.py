"""Verify actual Windows Event Logs when running on Windows."""
import os

import pytest

from src.app import dashboard_snapshot, ingest_payloads
from src.windows_collector import WindowsEventCollector


@pytest.mark.skipif(os.name != "nt", reason="Native Windows Event Logs require Windows")
def test_actual_system_events_update_dashboard(tmp_path):
    db = tmp_path / "native.db"
    collector = WindowsEventCollector(db, ingest_payloads, channels=("System",), backfill_per_channel=3)
    assert dashboard_snapshot(db)["counts"]["Total"] == 0
    records = collector._recent_records("System")
    assert records, "The Windows test machine must have real System log records"
    collector._ingest_records("System", records, backfill=True)
    snapshot = dashboard_snapshot(db)
    assert snapshot["counts"]["Total"] == len(records)
    assert all(event["source"] == "windows-event-log" for event in snapshot["events"])
    assert all(event["record_id"] for event in snapshot["events"])
    # Exercise a normal quiet/current-cursor poll against the actual Windows cmdlet.
    current = collector.cursors["System"]
    later = collector._new_records("System", current)
    assert all(int(record["RecordId"]) > current for record in later)
