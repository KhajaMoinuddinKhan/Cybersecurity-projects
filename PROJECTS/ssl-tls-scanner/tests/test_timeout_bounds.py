"""Regression test for out-of-range timeout handling."""
import subprocess
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]


def test_out_of_range_timeout_exits_without_traceback():
    # "1e300"/"inf" is accepted by argparse but overflows PyTime_t inside
    # socket.settimeout(); the CLI must report it instead of dumping a traceback.
    result = subprocess.run(
        [
            sys.executable, "-m", "src.scanner",
            "127.0.0.1", "--port", "443", "--timeout", "1e300",
        ],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
    )
    assert "TLS assessment failed" in result.stderr
    assert "Traceback" not in result.stderr
