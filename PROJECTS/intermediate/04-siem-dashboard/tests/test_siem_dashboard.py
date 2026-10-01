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
    seed_events,
    severity_counts,
)


def test_seed_and_query_by_severity(tmp_path: Path):
    db = tmp_path / "siem.db"
    events = [
        ("2026-09-30 09:00", "10.0.0.1", "Failed login", "high", "admin"),
        ("2026-09-30 09:01", "10.0.0.2", "Normal login", "Low", "user"),
    ]
    assert seed_events(db, events) == 2
    assert len(query_events(db)) == 2
    assert len(query_events(db, "HIGH")) == 1
    assert query_events(db, "High")[0][3] == "Failed login"


def test_structured_ingestion_populates_live_fields(tmp_path: Path):
    db = tmp_path / "siem.db"
    assert ingest_payloads(
        db,
        [{
            "timestamp": "2026-10-01T12:00:00Z",
            "source_ip": "192.0.2.10",
            "event": "Endpoint blocked script",
            "severity": "High",
            "username": "analyst",
            "host": "ws-01",
            "source": "edr",
            "event_type": "endpoint_alert",
        }],
    ) == 1
    row = query_events(db)[0]
    assert row[2] == "192.0.2.10"
    assert row[6] == "ws-01"
    assert row[7] == "edr"
    assert row[8] == "endpoint_alert"


def test_search_and_filtered_counts(tmp_path: Path):
    db = tmp_path / "siem.db"
    ingest_payloads(
        db,
        [
            {"event":"Failed VPN login","severity":"High","source_ip":"10.0.0.1","username":"admin","source":"vpn","event_type":"authentication"},
            {"event":"Normal login","severity":"Low","source_ip":"10.0.0.2","username":"user","source":"vpn","event_type":"authentication"},
            {"event":"Malware blocked","severity":"Medium","source_ip":"10.0.0.3","username":"analyst","source":"edr","event_type":"endpoint_alert"},
        ],
    )
    assert len(query_events(db, search="VPN")) == 1
    assert len(query_events(db, source="edr")) == 1
    assert severity_counts(db, source="vpn") == {
        "High": 1, "Medium": 0, "Low": 1, "Total": 2
    }


def test_search_treats_sql_wildcards_as_literal_text(tmp_path: Path):
    db = tmp_path / "siem.db"
    seed_events(
        db,
        [
            ("2026-09-30 09:00", "10.0.0.1", "CPU at 90% threshold", "Low", "system"),
            ("2026-09-30 09:01", "10.0.0.2", "Normal login", "Low", "user"),
        ],
    )
    assert len(query_events(db, search="%")) == 1


def test_invalid_severity_is_rejected(tmp_path: Path):
    db = tmp_path / "siem.db"
    with pytest.raises(ValueError, match="Unsupported severity"):
        ingest_payloads(db, [{"event":"Unexpected","severity":"Critical"}])


def test_reset_events_clears_rows_and_restarts_ids(tmp_path: Path):
    db = tmp_path / "siem.db"
    seed_events(db, [("2026-09-30 09:00","10.0.0.1","One","High","admin")])
    reset_events(db)
    seed_events(db, [("2026-09-30 09:01","10.0.0.2","Two","Low","user")])
    rows = query_events(db)
    assert len(rows) == 1
    assert rows[0][0] == 1


def test_jsonl_and_csv_imports():
    jsonl = b'{"event":"One","severity":"High"}\n{"event":"Two","severity":"Low"}\n'
    assert len(parse_event_file("events.jsonl", jsonl)) == 2
    csv_data = b"event,severity,source_ip\nLogin,Medium,192.0.2.4\n"
    rows = parse_event_file("events.csv", csv_data)
    assert rows[0]["event"] == "Login"


def test_dashboard_snapshot_contains_live_analytics(tmp_path: Path):
    db = tmp_path / "siem.db"
    ingest_payloads(
        db,
        [
            {"event":"Failed login","severity":"High","source_ip":"10.0.0.9","source":"vpn","event_type":"authentication"},
            {"event":"Blocked process","severity":"Medium","source_ip":"10.0.0.8","source":"edr","event_type":"endpoint_alert"},
        ],
    )
    snapshot = dashboard_snapshot(db)
    assert snapshot["counts"]["Total"] == 2
    assert snapshot["top_sources"][0]["count"] == 1
    assert "vpn" in snapshot["dimensions"]["sources"]


def test_dashboard_api_ingests_and_filters_events(tmp_path: Path):
    db = tmp_path / "siem.db"
    app = dashboard_app(db)
    app.testing = True
    client = app.test_client()

    page = client.get("/")
    assert page.status_code == 200
    assert b"MKMK SIEM Console" in page.data
    assert b"LIVE EVENT STREAM" in page.data

    created = client.post(
        "/api/events",
        json={
            "event":"Repeated login failures",
            "severity":"High",
            "source_ip":"198.51.100.20",
            "username":"admin",
            "host":"vpn-01",
            "source":"vpn",
            "event_type":"authentication",
        },
    )
    assert created.status_code == 201
    assert created.get_json()["inserted"] == 1

    dashboard = client.get("/api/dashboard?severity=High&source=vpn")
    data = dashboard.get_json()
    assert data["counts"]["Total"] == 1
    assert data["events"][0]["host"] == "vpn-01"


def test_file_import_endpoint(tmp_path: Path):
    db = tmp_path / "siem.db"
    app = dashboard_app(db)
    app.testing = True
    client = app.test_client()

    payload = json.dumps([
        {"event":"Firewall deny","severity":"Medium","source":"firewall","event_type":"network"}
    ]).encode()
    response = client.post(
        "/api/import",
        data={"file": (io.BytesIO(payload), "events.json")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 201
    assert response.get_json()["inserted"] == 1
