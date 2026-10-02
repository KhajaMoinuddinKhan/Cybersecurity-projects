"""Regression tests for query-parameter parsing and raw-record fidelity."""

import json

from src.app import dashboard_app


def _client(tmp_path):
    app = dashboard_app(tmp_path / "live.db")
    app.testing = True
    return app.test_client()


def _seed(client):
    response = client.post(
        "/api/events",
        json=[
            {"message": "rule hit", "severity": "High", "is_alert": True},
            {"message": "ordinary", "severity": "Low", "is_alert": False},
        ],
    )
    assert response.status_code == 201


def test_boolean_alert_spellings_select_only_alerts(tmp_path):
    client = _client(tmp_path)
    _seed(client)
    for spelling in ("1", "true", "True", "yes", "on"):
        data = client.get(f"/api/dashboard?alerts={spelling}").get_json()
        assert data["counts"]["Total"] == 1, spelling
        assert [event["message"] for event in data["events"]] == ["rule hit"], spelling
    for spelling in ("0", "false", ""):
        data = client.get(f"/api/dashboard?alerts={spelling}").get_json()
        assert data["counts"]["Total"] == 2, spelling


def test_since_rejects_non_decimal_digits_with_the_documented_message(tmp_path):
    client = _client(tmp_path)
    for encoded in ("%C2%B2", "%D9%A3"):  # superscript two, Arabic-Indic three
        response = client.get(f"/api/dashboard?since={encoded}")
        assert response.status_code == 400
        assert response.is_json
        assert response.get_json()["error"] == "since must be a whole number of minutes"


def test_structured_raw_log_is_stored_as_json(tmp_path):
    client = _client(tmp_path)
    raw = {"EventID": 4625, "User": "admin", "nested": {"a": [1, 2]}}
    assert client.post(
        "/api/events", json={"message": "raw record", "raw_log": raw}
    ).status_code == 201
    events = client.get("/api/dashboard?search=raw%20record").get_json()["events"]
    assert len(events) == 1
    stored = events[0]["raw_log"]
    assert isinstance(stored, str)
    assert json.loads(stored) == raw
