"""Exercise the shipped JavaScript controls against a real temporary Flask API."""
import os
from pathlib import Path
import shutil
import subprocess
import threading

import pytest
from werkzeug.serving import make_server

from src.app import dashboard_app


def test_dashboard_controls(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for JavaScript control verification")
    server = make_server("127.0.0.1", 0, dashboard_app(tmp_path / "controls.db"), threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        environment = {**os.environ, "SIEM_TEST_URL": f"http://127.0.0.1:{server.server_port}"}
        result = subprocess.run(
            [node, str(Path(__file__).with_name("dashboard_ui.cjs"))],
            env=environment, capture_output=True, text=True, timeout=40,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
