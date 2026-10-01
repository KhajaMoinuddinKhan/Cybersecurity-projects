import io
import json
from pathlib import Path

import pytest

from src.app import (
    dashboard_app,
    dashboard_snapshot,
    ingest_payloads,
    parse_event_file,
    query_events,
    reset_events,
)
from src.windows_collector import (
    classify_event,
    severity_from_windows_level,
    windows_event_to_payload,
)


def test_live_store_starts_empty(tmp_path: Path):
    db = tmp_path / "siem_live.db"
    assert dashboard_snapshot(db)["counts"]["Total"] == 0


def test_real_windows_event_mapping_extracts_fields():
    payload = windows_event_to_payload(
        "Security",
        {
            "RecordId": 4421,
            "Id": 4625,
            "TimeCreated": "2026-10-01T15:10:00+00:00",
            "Level": "Information",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Machine": "DESKTOP-LAB",
            "User": "S-1-5-18",
            "Message": "An account failed to log on.",
            "Xml": """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <EventData>
              <Data Name="TargetUserName">admin</Data>
              <Data Name="IpAddress">192.0.2.25</Data>
            </EventData>
            </Event>""",
        },
    )
    assert payload["channel"] == "Security"
    assert payload["event_id"] == "4625"
    assert payload["username"] == "admin"
    assert payload["source_ip"] == "192.0.2.25"
    assert payload["is_alert"] is True
    assert payload["rule_name"] == "Failed Windows logon"


def test_windows_security_rules_are_event_based():
    assert classify_event("Security", "1102", "Information", "x") == (
        "High", True, "Windows audit log cleared"
    )
    assert classify_event("System", "7045", "Information", "x") == (
        "High", True, "Windows service installed"
    )
    severity, alert, rule = classify_event(
        "Microsoft-Windows-PowerShell/Operational",
        "4104",
        "Information",
        "powershell -enc AAAA",
    )
    assert severity == "High"
    assert alert is True
    assert rule == "Suspicious PowerShell script block"


def test_windows_level_fallback():
    assert severity_from_windows_level("Critical") == "High"
    assert severity_from_windows_level("Error") == "High"
    assert severity_from_windows_level("Warning") == "Medium"
    assert severity_from_windows_level("Information") == "Low"


def test_ingestion_changes_dashboard_values(tmp_path: Path):
    db = tmp_path / "siem_live.db"
    inserted = ingest_payloads(
        db,
        [
            {
                "timestamp": "2026-10-01T12:00:00Z",
                "channel": "System",
                "provider": "Service Control Manager",
                "event_id": "7045",
                "level": "Information",
                "severity": "High",
                "username": "SYSTEM",
                "host": "LAB-PC",
                "source_ip": "local",
                "message": "A service was installed.",
                "record_id": "500",
                "source": "windows-event-log",
                "is_alert": True,
                "rule_name": "Windows service installed",
                "external_id": "System:500",
            }
        ],
    )
    assert inserted == 1
    snapshot = dashboard_snapshot(db)
    assert snapshot["counts"]["Total"] == 1
    assert snapshot["counts"]["High"] == 1
    assert snapshot["alert_count"] == 1
    assert snapshot["events"][0]["provider"] == "Service Control Manager"


def test_duplicate_windows_records_are_ignored(tmp_path: Path):
    db = tmp_path / "siem_live.db"
    payload = {
        "message": "System event",
        "severity": "Low",
        "channel": "System",
        "provider": "Kernel-General",
        "event_id": "12",
        "source": "windows-event-log",
        "external_id": "System:99",
    }
    assert ingest_payloads(db, [payload]) == 1
    assert ingest_payloads(db, [payload]) == 0
    assert dashboard_snapshot(db)["counts"]["Total"] == 1


def test_filters_use_live_values(tmp_path: Path):
    db = tmp_path / "siem_live.db"
    ingest_payloads(
        db,
        [
            {"message":"Failed logon","severity":"Medium","channel":"Security","provider":"Security-Auditing","event_id":"4625","username":"admin","source_ip":"192.0.2.10","is_alert":True,"rule_name":"Failed Windows logon"},
            {"message":"Application started","severity":"Low","channel":"Application","provider":"DemoProvider","event_id":"100","username":"user"},
        ],
    )
    assert len(query_events(db, channel="Security")) == 1
    assert len(query_events(db, provider="DemoProvider")) == 1
    assert len(query_events(db, alerts_only=True)) == 1
    assert dashboard_snapshot(db, severity="Medium")["counts"]["Total"] == 1


def test_reset_clears_live_store(tmp_path: Path):
    db = tmp_path / "siem_live.db"
    ingest_payloads(db, [{"message":"One","severity":"Low"}])
    reset_events(db)
    assert dashboard_snapshot(db)["counts"]["Total"] == 0


def test_jsonl_and_csv_imports():
    jsonl = b'{"message":"One","severity":"High"}\n{"message":"Two","severity":"Low"}\n'
    assert len(parse_event_file("events.jsonl", jsonl)) == 2

    csv_data = b"message,severity,event_id\nLogin,Medium,4625\n"
    rows = parse_event_file("events.csv", csv_data)
    assert rows[0]["event_id"] == "4625"


def test_dashboard_api_returns_dynamic_data(tmp_path: Path):
    db = tmp_path / "siem_live.db"
    app = dashboard_app(db)
    app.testing = True
    client = app.test_client()

    page = client.get("/")
    assert page.status_code == 200
    assert b"Live SIEM Console" in page.data

    created = client.post(
        "/api/events",
        json={
            "message":"External collector event",
            "severity":"High",
            "channel":"EDR",
            "provider":"EndpointAgent",
            "event_id":"9001",
            "is_alert":True,
            "rule_name":"Endpoint detection",
        },
    )
    assert created.status_code == 201

    data = client.get("/api/dashboard?channel=EDR").get_json()
    assert data["counts"]["Total"] == 1
    assert data["alert_count"] == 1
    assert data["events"][0]["event_id"] == "9001"


def test_file_import_endpoint(tmp_path: Path):
    db = tmp_path / "siem_live.db"
    app = dashboard_app(db)
    app.testing = True
    client = app.test_client()

    payload = json.dumps([
        {"message":"Firewall deny","severity":"Medium","channel":"Firewall","event_id":"77"}
    ]).encode()
    response = client.post(
        "/api/import",
        data={"file": (io.BytesIO(payload), "events.json")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 201
    assert response.get_json()["inserted"] == 1


def test_invalid_severity_is_rejected(tmp_path: Path):
    db = tmp_path / "siem_live.db"
    with pytest.raises(ValueError, match="Unsupported severity"):
        ingest_payloads(db, [{"message":"Unexpected","severity":"Critical"}])
