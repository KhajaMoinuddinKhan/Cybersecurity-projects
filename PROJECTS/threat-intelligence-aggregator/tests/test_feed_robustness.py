"""Regression tests for feed encoding and parser robustness."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.aggregator import read_feed

PROJECT_DIR = Path(__file__).resolve().parents[1]


def _run_cli(*args):
    """Invoke the documented command line in a separate interpreter."""

    return subprocess.run(
        [sys.executable, "-m", "src.aggregator", *args],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
    )


def test_read_feed_accepts_utf8_bom_csv(tmp_path):
    path = tmp_path / "bom.csv"
    path.write_bytes("type,value,source\nip,9.9.9.9,bom-feed\n".encode("utf-8-sig"))
    assert read_feed(path) == [("ip", "9.9.9.9", "bom-feed")]


def test_read_feed_accepts_utf8_bom_json(tmp_path):
    path = tmp_path / "bom.json"
    payload = json.dumps([{"type": "ip", "value": "8.8.8.8"}])
    path.write_bytes(payload.encode("utf-8-sig"))
    assert read_feed(path) == [("ip", "8.8.8.8", "local")]


def test_read_feed_reports_missing_required_columns(tmp_path):
    path = tmp_path / "missing.csv"
    path.write_text("foo,bar\n1,2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing required column"):
        read_feed(path)


def test_oversized_csv_field_exits_without_traceback(tmp_path):
    path = tmp_path / "large.csv"
    path.write_text(
        "type,value,source\nurl," + "a" * 200000 + ",feed\n", encoding="utf-8"
    )
    result = _run_cli("--feed", str(path), "--db", str(tmp_path / "large.db"))
    assert result.returncode != 0
    assert "Feed operation failed" in result.stderr
    assert "Traceback" not in result.stderr


def test_deeply_nested_json_exits_without_traceback(tmp_path):
    path = tmp_path / "deep.json"
    path.write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
    result = _run_cli("--feed", str(path), "--db", str(tmp_path / "deep.db"))
    assert result.returncode != 0
    assert "Feed operation failed" in result.stderr
    assert "Traceback" not in result.stderr
