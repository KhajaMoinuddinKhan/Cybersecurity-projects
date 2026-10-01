import io
from src.app import dashboard_app


def test_extra_csv_columns_return_helpful_error(tmp_path):
    client = dashboard_app(tmp_path / "live.db").test_client()
    response = client.post("/api/import", data={"file": (io.BytesIO(b"message,severity\nhello,Low,extra\n"), "events.csv")})
    assert response.status_code == 400
    assert "columns" in response.get_json()["error"]
