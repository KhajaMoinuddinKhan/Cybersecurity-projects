"""A real MQTT broker, run as a real process.

The IoT arm is the one that talks to a service rather than reading a file, so its
fixture has to be a service. This starts an actual broker -- amqtt, the same broker
the audit is aimed at -- in two configurations, so both answers can be produced
rather than described:

  * `open`       accepts connections from anybody, which is the finding
  * `closed`     refuses anonymous connections, which is the control satisfied

Both are needed. A check that fires on the vulnerable configuration and also fires on
the hardened one is not detecting anything, and there is no way to tell the two apart
from the first case alone.

The broker is started as a subprocess rather than in a thread because amqtt wants a
running event loop when it is constructed, and because a fixture that shares a
process with the thing it tests is the arrangement that hid the harness bug in the
detection project.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

__all__ = ["Broker", "find_amqtt"]

CONFIG_TEMPLATE = """listeners:
  default:
    type: tcp
    bind: {host}:{port}
sys_interval: 0
auth:
  allow-anonymous: {allow_anonymous}
topic-check:
  enabled: false
"""


def find_amqtt() -> str | None:
    """The broker executable, next to the interpreter that is running this."""
    scripts = Path(sys.executable).resolve().parent
    for name in ("amqtt.exe", "amqtt"):
        candidate = scripts / name
        if candidate.exists():
            return str(candidate)
    return None


class Broker:
    """An MQTT broker on loopback, in a subprocess, for as long as the block runs."""

    def __init__(self, port: int = 0, host: str = "127.0.0.1",
                 allow_anonymous: bool = True, start_timeout: float = 20.0):
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("the lab broker binds to loopback only; refusing %r" % host)
        executable = find_amqtt()
        if not executable:
            raise RuntimeError("amqtt is not installed beside this interpreter, so the "
                               "lab cannot start a real broker")
        self.host = host
        self.port = port or _free_port(host)
        self.allow_anonymous = allow_anonymous
        self.executable = executable
        self.start_timeout = start_timeout
        self.process: subprocess.Popen | None = None
        self.config_path: Path | None = None

    def start(self) -> "Broker":
        self.config_path = Path(__file__).resolve().parent / (
            "_broker-%s.yaml" % ("open" if self.allow_anonymous else "closed"))
        self.config_path.write_text(CONFIG_TEMPLATE.format(
            host=self.host, port=self.port,
            allow_anonymous="true" if self.allow_anonymous else "false"),
            encoding="utf-8")
        self.process = subprocess.Popen(
            [self.executable, "-c", str(self.config_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        deadline = time.monotonic() + self.start_timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("the broker exited immediately: %s"
                                   % (self.process.stdout.read() or "")[-400:])
            try:
                with socket.create_connection((self.host, self.port), timeout=1):
                    return self
            except OSError:
                time.sleep(0.25)
        self.stop()
        raise RuntimeError("the broker did not accept a connection within %.0fs"
                           % self.start_timeout)

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
        if self.config_path and self.config_path.exists():
            try:
                self.config_path.unlink()
            except OSError:
                pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    @property
    def address(self) -> str:
        return "%s:%d" % (self.host, self.port)


def _free_port(host: str) -> int:
    """An unused port, taken from the operating system rather than guessed at."""
    with socket.socket() as probe:
        probe.bind((host, 0))
        return probe.getsockname()[1]
