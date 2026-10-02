"""A deeply nested asset file must fail cleanly, not crash."""
import subprocess
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]


def test_deeply_nested_json_exits_without_traceback(tmp_path):
    path = tmp_path / "deep.json"
    path.write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "src.inventory", str(path)],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Invalid asset file" in result.stderr
    assert "Traceback" not in result.stderr
