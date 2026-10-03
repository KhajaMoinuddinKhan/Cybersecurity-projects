"""Report formats, the --report file and the exit codes."""
import json
import subprocess
import sys
from pathlib import Path

from src.fim import Change, format_json, format_text, summary_counts


def _create(folder: Path, baseline: Path) -> None:
    subprocess.run(
        [sys.executable, "-m", "src.fim", str(folder), "--baseline", str(baseline), "--create"],
        check=True, capture_output=True,
    )


def _run(folder: Path, baseline: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "src.fim", str(folder), "--baseline", str(baseline), *extra],
        capture_output=True, text=True,
    )


def test_text_report_lists_changes_and_a_summary():
    changes = [Change("ADDED", "a.txt"), Change("MODIFIED", "b.txt", "size, mtime"), Change("REMOVED", "c.txt")]
    text = format_text(changes)
    assert "Integrity changes detected:" in text
    assert "ADDED" in text and "a.txt" in text
    assert "Summary: 1 added, 1 modified, 1 removed" in text


def test_text_report_for_a_clean_folder():
    assert format_text([]) == "No integrity changes detected."


def test_json_report_has_type_path_and_detail():
    changes = [Change("PERMISSIONS", "b.txt", "0o100644 -> 0o100444")]
    payload = json.loads(format_json(changes))
    assert payload["changes"] == [{"type": "PERMISSIONS", "path": "b.txt", "detail": "0o100644 -> 0o100444"}]
    assert payload["summary"]["PERMISSIONS"] == 1
    assert payload["total"] == 1


def test_summary_counts_every_kind():
    assert summary_counts([Change("ADDED", "a")]) == {"ADDED": 1, "MODIFIED": 0, "REMOVED": 0, "PERMISSIONS": 0}


def test_exit_code_is_non_zero_when_changes_are_found(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)
    (folder / "one.txt").write_text("changed", encoding="utf-8")
    result = _run(folder, baseline)
    assert result.returncode == 1
    assert "Integrity changes detected:" in result.stdout


def test_exit_code_is_zero_when_nothing_changed(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)
    result = _run(folder, baseline)
    assert result.returncode == 0
    assert "No integrity changes" in result.stdout


def test_json_flag_prints_a_json_report(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)
    (folder / "two.txt").write_text("two", encoding="utf-8")
    result = _run(folder, baseline, "--json")
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["changes"][0]["type"] == "ADDED"
    assert payload["changes"][0]["path"] == "two.txt"


def test_report_option_writes_the_findings_to_a_file(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)
    (folder / "two.txt").write_text("two", encoding="utf-8")
    report = tmp_path / "report.txt"
    result = _run(folder, baseline, "--report", str(report))
    assert result.returncode == 1
    written = report.read_text(encoding="utf-8")
    assert "ADDED" in written and "two.txt" in written
    assert written.strip() == result.stdout.strip()


def test_json_report_option_writes_json_to_the_file(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)
    (folder / "two.txt").write_text("two", encoding="utf-8")
    report = tmp_path / "report.json"
    result = _run(folder, baseline, "--json", "--report", str(report))
    assert result.returncode == 1
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["changes"][0]["path"] == "two.txt"
