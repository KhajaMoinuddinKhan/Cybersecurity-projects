"""The store can be written out as CSV or JSON."""
import csv
import json
from datetime import datetime, timezone

import pytest

from src.aggregator import export_iocs, import_indicators

NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)


def _seed(db):
    import_indicators(
        db,
        [("ip", "198.51.100.23", "feed-a"), ("ip", "198.51.100.23", "feed-b")],
        now=NOW,
    )
    import_indicators(db, [("domain", "bad.example", "feed-a")], now=NOW)


def test_export_csv_has_a_header_and_one_row_per_indicator(tmp_path):
    db = tmp_path / "intel.db"
    _seed(db)
    out = tmp_path / "intel.csv"

    assert export_iocs(db, out, now=NOW) == 2

    with out.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["value"] for row in rows] == ["bad.example", "198.51.100.23"]
    assert rows[1]["sources"] == "feed-a;feed-b"
    assert rows[1]["observations"] == "2"


def test_export_json_is_a_list_of_records(tmp_path):
    db = tmp_path / "intel.db"
    _seed(db)
    out = tmp_path / "intel.json"

    assert export_iocs(db, out, now=NOW) == 2

    records = json.loads(out.read_text(encoding="utf-8"))
    assert records[0]["type"] == "domain"
    assert records[0]["confidence"] == 0.6
    assert records[0]["age_band"] == "0-7d"


def test_export_format_can_be_forced(tmp_path):
    db = tmp_path / "intel.db"
    _seed(db)
    out = tmp_path / "intel.data"
    export_iocs(db, out, fmt="json", now=NOW)
    assert json.loads(out.read_text(encoding="utf-8"))


def test_export_rejects_an_unknown_format(tmp_path):
    db = tmp_path / "intel.db"
    _seed(db)
    with pytest.raises(ValueError, match="unsupported export format"):
        export_iocs(db, tmp_path / "intel.txt", now=NOW)
