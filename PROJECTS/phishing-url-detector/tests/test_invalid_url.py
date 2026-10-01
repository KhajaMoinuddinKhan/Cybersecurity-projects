import subprocess
import sys


def test_bad_url_does_not_hide_later_results():
    result = subprocess.run([sys.executable, "-m", "src.detector", "http://[", "https://example.com"], capture_output=True, text=True)
    assert result.returncode != 0
    assert "Invalid URL" in result.stderr
    assert "Traceback" not in result.stderr
    assert "Score: 0" in result.stdout
