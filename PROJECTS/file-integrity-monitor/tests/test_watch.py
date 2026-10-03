"""Watch mode re-scans on an interval and stops after --count scans."""
import json
import subprocess
import sys
from pathlib import Path


def _create(folder: Path, baseline: Path) -> None:
    subprocess.run(
        [sys.executable, "-m", "src.fim", str(folder), "--baseline", str(baseline), "--create"],
        check=True, capture_output=True,
    )


def _watch(folder: Path, baseline: Path, count: int, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "src.fim", str(folder), "--baseline", str(baseline),
         "--watch", "--count", str(count), "--interval", "0.1", *extra],
        capture_output=True, text=True, timeout=60,
    )


def test_a_single_watch_scan_reports_changes_and_exits(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)
    (folder / "one.txt").write_text("changed", encoding="utf-8")
    (folder / "two.txt").write_text("two", encoding="utf-8")
    result = _watch(folder, baseline, 1)
    assert result.returncode == 1
    assert "Scan 1:" in result.stdout
    assert "MODIFIED" in result.stdout and "one.txt" in result.stdout
    assert "ADDED" in result.stdout and "two.txt" in result.stdout


def test_a_watch_scan_with_no_changes_exits_zero(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)
    result = _watch(folder, baseline, 1)
    assert result.returncode == 0
    assert "Scan 1: 0 changes" in result.stdout


def test_watch_reports_a_change_once_and_not_on_every_scan(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)
    (folder / "one.txt").write_text("changed", encoding="utf-8")
    result = _watch(folder, baseline, 3)
    assert result.returncode == 1
    assert result.stdout.count("MODIFIED") == 1
    assert "Scan 1: 1 change" in result.stdout
    assert "Scan 2: 0 changes" in result.stdout
    assert "Scan 3: 0 changes" in result.stdout


def test_watch_json_prints_one_object_per_scan(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)
    (folder / "two.txt").write_text("two", encoding="utf-8")
    result = _watch(folder, baseline, 1, "--json")
    assert result.returncode == 1
    objects = [line for line in result.stdout.splitlines() if line.startswith("{")]
    payload = json.loads(objects[-1])
    assert payload["scan"] == 1
    assert payload["changes"][0]["type"] == "ADDED"
    assert payload["changes"][0]["path"] == "two.txt"


def test_report_is_rejected_in_watch_mode(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)
    result = _watch(folder, baseline, 1, "--report", str(tmp_path / "report.txt"))
    assert result.returncode != 0
    assert "cannot be combined with --watch" in result.stderr
