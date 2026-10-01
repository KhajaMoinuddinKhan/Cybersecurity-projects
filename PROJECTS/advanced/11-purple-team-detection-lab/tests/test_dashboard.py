from pathlib import Path

from src.dashboard import render_dashboard
from src.storage import replace_alerts


def test_dashboard_starts_with_empty_website_alerts(tmp_path: Path):
    db = tmp_path / "alerts.db"
    replace_alerts(db, [])
    page = render_dashboard(db)
    assert "Purple Team Detection Lab" in page
    assert 'id="website-total">0<' in page
    assert "Website alert queue" in page
    assert "Scan a website to generate alerts." in page
