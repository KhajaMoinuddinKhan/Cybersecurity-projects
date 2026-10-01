"""A baseline saved by an editor, or with upper-case hex, must still load."""
import json
import subprocess
import sys
from pathlib import Path

from src.fim import build_baseline, compare_baseline, load_baseline


def test_baseline_saved_with_a_byte_order_mark_still_loads(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(build_baseline(folder), indent=2), encoding="utf-8-sig")
    assert baseline.read_bytes().startswith(b"\xef\xbb\xbf")
    assert compare_baseline(folder, load_baseline(baseline)) == []


def test_the_command_accepts_a_byte_order_mark_baseline(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    create = [sys.executable, "-m", "src.fim", str(folder), "--baseline", str(baseline), "--create"]
    subprocess.run(create, check=True, capture_output=True)
    baseline.write_text(baseline.read_text(encoding="utf-8"), encoding="utf-8-sig")
    result = subprocess.run(
        [sys.executable, "-m", "src.fim", str(folder), "--baseline", str(baseline)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "No integrity changes" in result.stdout


def test_upper_case_hex_digest_is_accepted_and_normalised(tmp_path: Path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("one", encoding="utf-8")
    metadata = build_baseline(folder)["one.txt"]
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"one.txt": {"sha256": metadata["sha256"].upper(), "size": metadata["size"]}}),
        encoding="utf-8",
    )
    loaded = load_baseline(baseline)
    assert loaded["one.txt"]["sha256"] == metadata["sha256"]
    assert compare_baseline(folder, loaded) == []
