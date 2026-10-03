"""The command line aggregates several feeds and reports on the store."""
import json
import subprocess
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "src.aggregator", *args],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
    )


def test_several_feeds_merge_and_name_their_sources(tmp_path):
    db = tmp_path / "intel.db"
    first = tmp_path / "first.csv"
    first.write_text("type,value\nip,198.51.100.23\n", encoding="utf-8")
    second = tmp_path / "second.json"
    second.write_text(
        json.dumps(
            [
                {"type": "ip", "value": "198.51.100.23"},
                {"type": "domain", "value": "bad.example"},
            ]
        ),
        encoding="utf-8",
    )

    imported = _run_cli("--feed", str(first), "--feed", str(second), "--db", str(db))
    assert imported.returncode == 0
    assert "Imported 2 new indicators (1 updated)." in imported.stdout

    found = _run_cli("--search", "198.51.100.23", "--db", str(db))
    assert found.returncode == 0
    assert "first.csv" in found.stdout
    assert "second.json" in found.stdout


def test_a_directory_of_feeds_is_imported(tmp_path):
    db = tmp_path / "intel.db"
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "a.csv").write_text("type,value\nip,198.51.100.23\n", encoding="utf-8")
    (feeds / "b.json").write_text(
        json.dumps([{"type": "domain", "value": "bad.example"}]), encoding="utf-8"
    )
    (feeds / "ignored.txt").write_text("not a feed", encoding="utf-8")

    result = _run_cli("--feed-dir", str(feeds), "--db", str(db))
    assert result.returncode == 0
    assert "Imported 2 new indicators" in result.stdout

    stats = _run_cli("--stats", "--db", str(db))
    assert "Total indicators: 2" in stats.stdout
    assert "a.csv" in stats.stdout and "b.json" in stats.stdout


def test_malformed_rows_are_counted_not_fatal(tmp_path):
    db = tmp_path / "intel.db"
    feed = tmp_path / "mixed.csv"
    feed.write_text(
        "type,value\nip,198.51.100.23\nip,999.1.1.1\nhash,abc123\n",
        encoding="utf-8",
    )

    result = _run_cli("--feed", str(feed), "--db", str(db))
    assert result.returncode == 0
    assert "Imported 1 new indicators" in result.stdout
    assert "Skipped 2 malformed entries" in result.stdout


def test_stats_and_export_commands(tmp_path):
    db = tmp_path / "intel.db"
    feed = tmp_path / "feed.csv"
    feed.write_text("type,value,source\nip,198.51.100.23,lab\n", encoding="utf-8")
    _run_cli("--feed", str(feed), "--db", str(db))

    stats = _run_cli("--stats", "--db", str(db))
    assert "Total indicators: 1" in stats.stdout
    assert "By source:" in stats.stdout

    out = tmp_path / "export.json"
    exported = _run_cli("--export", str(out), "--db", str(db))
    assert exported.returncode == 0
    assert "Exported 1 indicators" in exported.stdout
    assert json.loads(out.read_text(encoding="utf-8"))[0]["value"] == "198.51.100.23"


def test_expire_command_reports_the_pruning(tmp_path):
    db = tmp_path / "intel.db"
    feed = tmp_path / "feed.csv"
    feed.write_text("type,value\nip,198.51.100.23\n", encoding="utf-8")
    _run_cli("--feed", str(feed), "--db", str(db))

    # Nothing is old enough yet, so the run reports zero.
    result = _run_cli("--expire-days", "30", "--db", str(db))
    assert result.returncode == 0
    assert "Pruned 0 stale indicators" in result.stdout
