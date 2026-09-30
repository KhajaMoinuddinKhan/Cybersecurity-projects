from pathlib import Path
from src.fim import build_baseline, compare_baseline

def test_detects_added_modified_and_removed_files(tmp_path: Path):
    folder=tmp_path/"files"; folder.mkdir()
    original=folder/"original.txt"; removed=folder/"removed.txt"
    original.write_text("one",encoding="utf-8"); removed.write_text("remove me",encoding="utf-8")
    baseline=build_baseline(folder)
    removed.unlink(); original.write_text("changed",encoding="utf-8")
    (folder/"added.txt").write_text("new",encoding="utf-8")
    changes=compare_baseline(folder,baseline)
    assert ("MODIFIED","original.txt") in changes
    assert ("REMOVED","removed.txt") in changes
    assert ("ADDED","added.txt") in changes
