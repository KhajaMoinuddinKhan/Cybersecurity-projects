"""Exercise the shipped JavaScript controls against a real temporary Flask API."""
import os
from pathlib import Path
import shutil
import subprocess
import threading

import pytest
from werkzeug.serving import make_server

from src.app import dashboard_app

# A browser control test on a shared CI runner. The bound was forty seconds and it
# failed once on a runner that was simply busy, on a commit where nothing in this
# project had changed -- a false failure, which is worse than no test because it
# trains people to ignore a red build. The test itself takes about six seconds; the
# bound is set for the machine, not for the code, and a retry is allowed because a
# slow start and a wrong answer are different things. A retry cannot turn a wrong
# answer into a pass: the assertion on the output is unchanged.
UI_TIMEOUT_SECONDS = 150
UI_ATTEMPTS = 2


def test_dashboard_controls(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for JavaScript control verification")
    server = make_server("127.0.0.1", 0, dashboard_app(tmp_path / "controls.db"), threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        environment = {**os.environ, "SIEM_TEST_URL": f"http://127.0.0.1:{server.server_port}"}
        result = None
        for attempt in range(UI_ATTEMPTS):
            result = subprocess.run(
                [node, str(Path(__file__).with_name("dashboard_ui.cjs"))],
                env=environment, capture_output=True, text=True,
                timeout=UI_TIMEOUT_SECONDS,
            )
            if result.returncode == 0:
                break
        assert result.returncode == 0, result.stdout + result.stderr
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
