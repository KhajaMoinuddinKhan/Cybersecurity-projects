"""Regression tests for malformed-import crashes in the live SIEM store."""
import io

import pytest

from src.app import dashboard_app, dashboard_snapshot, parse_event_file

# Deep enough to exceed the interpreter recursion limit during json.loads.
DEEP_JSON = ("[" * 20000 + "0" + "]" * 20000).encode()


def _client(tmp_path):
    app = dashboard_app(tmp_path / "live.db")
    app.testing = True
    return app.test_client()


def test_deeply_nested_json_import_returns_json_400(tmp_path):
    client = _client(tmp_path)
    response = client.post(
        "/api/import",
        data={"file": (io.BytesIO(DEEP_JSON), "deep.json")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert response.is_json
    assert "error" in response.get_json()
    # A rejected batch must not leave a partially imported store.
    assert dashboard_snapshot(tmp_path / "live.db")["counts"]["Total"] == 0


def test_deeply_nested_jsonl_import_returns_json_400(tmp_path):
    client = _client(tmp_path)
    response = client.post(
        "/api/import",
        data={"file": (io.BytesIO(DEEP_JSON), "deep.jsonl")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert response.is_json


def test_deeply_nested_json_api_event_returns_json_400(tmp_path):
    client = _client(tmp_path)
    response = client.post(
        "/api/events",
        data=DEEP_JSON,
        content_type="application/json",
    )
    assert response.status_code == 400
    assert response.is_json
    assert "error" in response.get_json()
    assert dashboard_snapshot(tmp_path / "live.db")["counts"]["Total"] == 0


def test_deep_json_file_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="nested too deeply"):
        parse_event_file("deep.json", DEEP_JSON)
    with pytest.raises(ValueError, match="nested too deeply"):
        parse_event_file("deep.jsonl", DEEP_JSON)


def test_wide_csv_field_imports_instead_of_crashing(tmp_path):
    # 200k characters exceeds csv's default 131072-byte field limit.
    long_message = "z" * 200_000
    payload = ("message,severity\n" + long_message + ",Low\n").encode()
    client = _client(tmp_path)
    response = client.post(
        "/api/import",
        data={"file": (io.BytesIO(payload), "wide.csv")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 201
    assert response.get_json()["inserted"] == 1
    events = dashboard_snapshot(tmp_path / "live.db")["events"]
    assert len(events) == 1
    assert events[0]["message"] == long_message
