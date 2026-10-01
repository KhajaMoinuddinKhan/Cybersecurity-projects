from pathlib import Path

from src.dashboard import render_dashboard
from src.storage import replace_alerts


def test_dashboard_renders_empty_database(tmp_path: Path):
    db = tmp_path / "alerts.db"
    replace_alerts(db, [])
    page = render_dashboard(db)
    assert "Purple Team Detection Lab" in page
    assert "Total alerts" in page
    assert "No alerts match" in page
