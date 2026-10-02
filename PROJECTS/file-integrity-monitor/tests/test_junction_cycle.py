"""Regression: a junction that points at its own ancestor must not repeat files."""
import os
import subprocess
from pathlib import Path

import pytest

from src.fim import build_baseline


@pytest.mark.skipif(os.name != "nt", reason="junctions are Windows-only")
def test_a_junction_cycle_does_not_repeat_files(tmp_path: Path):
    folder = tmp_path / "watched"
    folder.mkdir()
    (folder / "real.txt").write_text("real", encoding="utf-8")

    link = folder / "loop"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(folder)],
        capture_output=True, text=True,
    )
    if created.returncode != 0:
        pytest.skip(f"could not create a junction: {created.stderr or created.stdout}")

    assert list(build_baseline(folder)) == ["real.txt"]
