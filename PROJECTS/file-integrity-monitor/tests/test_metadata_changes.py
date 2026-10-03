"""Size, modification time and mode are recorded and compared with the hash."""
import os
import stat
from pathlib import Path

from src.fim import build_baseline, compare_baseline, compare_metadata, scan


def _restore(path: Path) -> None:
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)


def test_baseline_records_size_mtime_and_mode(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    metadata = build_baseline(folder)["one.txt"]
    assert metadata["size"] == 3
    assert isinstance(metadata["mtime"], float)
    assert isinstance(metadata["mode"], int)


def test_a_permission_change_is_reported_as_its_own_change_type(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    target = folder / "one.txt"
    target.write_text("one", encoding="utf-8")
    baseline = build_baseline(folder)
    os.chmod(target, stat.S_IREAD)
    try:
        changes = scan(folder, baseline)
        assert [(change.kind, change.path) for change in changes] == [("PERMISSIONS", "one.txt")]
        assert changes[0].detail.startswith("0o")
    finally:
        _restore(target)


def test_a_permission_change_keeps_the_two_tuple_comparison(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    target = folder / "one.txt"
    target.write_text("one", encoding="utf-8")
    baseline = build_baseline(folder)
    os.chmod(target, stat.S_IREAD)
    try:
        assert ("PERMISSIONS", "one.txt") in compare_baseline(folder, baseline)
    finally:
        _restore(target)


def test_touching_a_file_without_editing_it_is_not_a_change(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    target = folder / "one.txt"
    target.write_text("one", encoding="utf-8")
    baseline = build_baseline(folder)
    moved = target.stat().st_mtime + 3600
    os.utime(target, (moved, moved))
    assert compare_baseline(folder, baseline) == []


def test_a_content_change_lists_the_metadata_that_moved_with_it(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    target = folder / "one.txt"
    target.write_text("one", encoding="utf-8")
    baseline = build_baseline(folder)
    target.write_text("one and more", encoding="utf-8")
    changes = scan(folder, baseline)
    assert changes[0].kind == "MODIFIED"
    assert "size" in changes[0].detail


def test_compare_metadata_lists_only_changed_fields():
    old = {"size": 1, "mtime": 1.0, "mode": 0o644}
    new = {"size": 2, "mtime": 2.0, "mode": 0o600}
    assert compare_metadata(old, new) == ["size", "mtime", "mode"]
    assert compare_metadata({"sha256": "x"}, {"sha256": "x"}) == []
