from pathlib import Path

import pytest

from src.app import (
    dashboard_app,
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


def test_search_and_severity_counts(tmp_path: Path):
    db = tmp_path / "siem.db"
    events = [
        ("2026-09-30 09:00", "10.0.0.1", "Failed VPN login", "High", "admin"),
        ("2026-09-30 09:01", "10.0.0.2", "Normal login", "Low", "user"),
        ("2026-09-30 09:02", "10.0.0.3", "New device", "Medium", "analyst"),
    ]
    seed_events(db, events)

    assert len(query_events(db, search="VPN")) == 1
    assert len(query_events(db, severity="High", search="admin")) == 1
    assert severity_counts(db) == {
        "High": 1,
        "Medium": 1,
        "Low": 1,
        "Total": 3,
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
    assert query_events(db, search="%")[0][3] == "CPU at 90% threshold"


def test_invalid_severity_is_rejected_during_ingestion(tmp_path: Path):
    db = tmp_path / "siem.db"

    with pytest.raises(ValueError, match="Unsupported severity"):
        seed_events(
            db,
            [
                (
                    "2026-09-30 09:00",
                    "10.0.0.1",
                    "Unexpected event",
                    "Critical",
                    "admin",
                )
            ],
        )


def test_reset_events_clears_rows_and_restarts_event_ids(tmp_path: Path):
    db = tmp_path / "siem.db"
    first_event = ("2026-09-30 09:00", "10.0.0.1", "Failed login", "High", "admin")
    second_event = ("2026-09-30 09:01", "10.0.0.2", "Normal login", "Low", "user")

    seed_events(db, [first_event])
    reset_events(db)
    seed_events(db, [second_event])

    rows = query_events(db)
    assert len(rows) == 1
    assert rows[0][0] == 1
    assert rows[0][3] == "Normal login"


def test_dashboard_renders_brand_filter_and_search(tmp_path: Path):
    db = tmp_path / "siem.db"
    seed_events(
        db,
        [
            ("2026-09-30 09:00", "10.0.0.1", "Failed login", "High", "admin"),
            ("2026-09-30 09:01", "10.0.0.2", "Normal login", "Low", "user"),
        ],
    )

    app = dashboard_app(db)
    app.testing = True
    client = app.test_client()

    response = client.get("/?severity=high&search=admin")
    assert response.status_code == 200
    assert b"MKMK SIEM Dashboard" in response.data
    assert b"Failed login" in response.data
    assert b"Normal login" not in response.data

    invalid_filter = client.get("/?severity=critical")
    assert invalid_filter.status_code == 200
    assert b"All Events" in invalid_filter.data
    assert b"Failed login" in invalid_filter.data
    assert b"Normal login" in invalid_filter.data
