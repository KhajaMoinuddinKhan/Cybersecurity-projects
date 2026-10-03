"""Exclude patterns keep cache and editor files out of a scan."""
import subprocess
import sys
from pathlib import Path

from src.fim import DEFAULT_EXCLUDES, build_baseline, is_excluded


def test_cache_and_editor_files_are_excluded_by_default(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "keep.txt").write_text("keep", encoding="utf-8")
    (folder / "__pycache__").mkdir()
    (folder / "__pycache__" / "module.cpython-311.pyc").write_text("x", encoding="utf-8")
    (folder / "editor.txt~").write_text("x", encoding="utf-8")
    (folder / ".DS_Store").write_text("x", encoding="utf-8")
    (folder / "scratch.tmp").write_text("x", encoding="utf-8")
    assert list(build_baseline(folder)) == ["keep.txt"]


def test_an_extra_exclude_pattern_removes_matching_files(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "keep.txt").write_text("keep", encoding="utf-8")
    (folder / "secret.key").write_text("k", encoding="utf-8")
    assert list(build_baseline(folder, patterns=["*.key"])) == ["keep.txt"]


def test_an_exclude_pattern_can_skip_a_directory_subtree(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "keep.txt").write_text("keep", encoding="utf-8")
    (folder / "build").mkdir()
    (folder / "build" / "out.bin").write_text("x", encoding="utf-8")
    assert list(build_baseline(folder, patterns=["build"])) == ["keep.txt"]


def test_an_exclude_pattern_can_match_a_relative_path(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "keep.txt").write_text("keep", encoding="utf-8")
    (folder / "logs").mkdir()
    (folder / "logs" / "app.log").write_text("x", encoding="utf-8")
    assert list(build_baseline(folder, patterns=["logs/*.log"])) == ["keep.txt"]


def test_is_excluded_matches_a_name_component_or_a_full_path():
    assert is_excluded("a/b/c.pyc", DEFAULT_EXCLUDES)
    assert is_excluded("__pycache__/x.py", DEFAULT_EXCLUDES)
    assert is_excluded("b/keep.txt", ["b"])
    assert is_excluded("a/b/keep.txt", ["a/b/keep.txt"])
    assert not is_excluded("a/b/keep.txt", DEFAULT_EXCLUDES)


def test_the_command_accepts_an_exclude_pattern(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "keep.txt").write_text("keep", encoding="utf-8")
    (folder / "secret.key").write_text("k", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    create = [sys.executable, "-m", "src.fim", str(folder), "--baseline", str(baseline), "--exclude", "*.key", "--create"]
    subprocess.run(create, check=True, capture_output=True)
    result = subprocess.run(
        [sys.executable, "-m", "src.fim", str(folder), "--baseline", str(baseline), "--exclude", "*.key"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "No integrity changes" in result.stdout


def test_a_default_excluded_file_is_not_reported_as_added(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    subprocess.run(
        [sys.executable, "-m", "src.fim", str(folder), "--baseline", str(baseline), "--create"],
        check=True, capture_output=True,
    )
    (folder / "new.tmp").write_text("scratch", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "src.fim", str(folder), "--baseline", str(baseline)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "new.tmp" not in result.stdout
