"""The since filter must accept minutes and refuse nonsense."""

from src.app import dashboard_app


def make_client(tmp_path):
    app = dashboard_app(tmp_path / "siem_live.db")
    app.testing = True
    return app.test_client()


def test_whole_number_of_minutes_is_accepted(tmp_path):
    client = make_client(tmp_path)
    client.post("/api/events", json={"message": "recent", "severity": "Low"})
    assert client.get("/api/dashboard?since=60").status_code == 200


def test_text_value_is_rejected_with_json_error(tmp_path):
    client = make_client(tmp_path)
    for bad in ("abc", "-5", "1e3"):
        response = client.get(f"/api/dashboard?since={bad}")
        assert response.status_code == 400
        assert "whole number of minutes" in response.get_json()["error"]


def test_absurd_value_is_rejected_instead_of_matching_nothing(tmp_path):
    client = make_client(tmp_path)
    client.post("/api/events", json={"message": "recent", "severity": "Low"})
    response = client.get("/api/dashboard?since=999999999999999999999")
    assert response.status_code == 400
    assert "since is limited to" in response.get_json()["error"]
    # the events are still there for a sane window
    assert client.get("/api/dashboard?since=60").get_json()["counts"]["Total"] == 1
