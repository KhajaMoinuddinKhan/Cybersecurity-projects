import json
import subprocess
import sys
import pytest
from src.fim import load_baseline


def test_cli_does_not_monitor_its_own_baseline(tmp_path):
    (tmp_path / "important.txt").write_text("unchanged")
    args = [sys.executable, "-m", "src.fim", str(tmp_path), "--baseline", str(tmp_path / "baseline.json")]
    subprocess.run([*args, "--create"], check=True, capture_output=True)
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    assert "No integrity changes" in result.stdout


@pytest.mark.parametrize("metadata", [None, [], {}, {"sha256": "bad"}])
def test_invalid_metadata_is_rejected(tmp_path, metadata):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"file.txt": metadata}))
    with pytest.raises(ValueError, match="metadata"):
        load_baseline(path)
