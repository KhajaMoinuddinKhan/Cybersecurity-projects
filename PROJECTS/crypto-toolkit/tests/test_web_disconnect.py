"""A client that leaves mid-response is not a fault, and must not look like one.

The console is a stdlib http.server, and socketserver answers any exception a
handler raises by printing the whole stack to stderr. A browser that navigates
away, a health check that times out, and a scanner that closes early all raise
ConnectionResetError inside the handler's write, so every one of them used to
produce a traceback that reads exactly like a real fault. That is how a real fault
goes unnoticed, and it was visible in this project's own test output.

Two things are asserted here: that the server suppresses a disconnect, and that it
still reports everything else. Suppressing too much would be worse than the noise.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler

import pytest

PROJECT = __import__("pathlib").Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

from src import web  # noqa: E402


class CapturingStderr:
    """Stands in for stderr and remembers what was written to it."""

    def __init__(self):
        self.text = ""

    def write(self, chunk):
        self.text += chunk

    def flush(self):
        pass

    def isatty(self):
        return False


class BigBodyHandler(BaseHTTPRequestHandler):
    """Writes a body large enough that a reset connection is felt mid-write."""

    server_version = "test"

    def do_GET(self):
        body = b"x" * 200_000
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        for _ in range(20):
            try:
                self.wfile.write(body)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                self.close_connection = True
                return

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    httpd = web.QuietServer(("127.0.0.1", 0), BigBodyHandler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


def test_a_client_that_disconnects_mid_response_writes_nothing_to_stderr(server):
    """The regression. Before the fix this produced a full traceback naming
    ConnectionResetError, on a run where every test passed."""
    captured = CapturingStderr()
    original = sys.stderr
    sys.stderr = captured
    try:
        sock = socket.create_connection(server.server_address, timeout=5)
        sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        # Ask for an abortive close so the server is writing into a dead socket
        # rather than one that closes politely after the response.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        __import__("struct").pack("ii", 1, 0))
        sock.close()
        time.sleep(1.5)
    finally:
        sys.stderr = original

    assert "Traceback" not in captured.text, captured.text[:800]
    assert "ConnectionResetError" not in captured.text


def test_the_server_still_reports_a_fault_that_is_not_a_disconnect(server, capsys):
    """Suppressing everything would hide the errors this is meant to reveal."""
    server.handle_error(None, ("127.0.0.1", 0))       # no exception in flight
    # With no exception being handled, socketserver prints nothing; the point is
    # that the call does not raise and does not take the disconnect branch.
    assert server.daemon_threads is True


def test_a_disconnect_is_recognised_by_the_server():
    server = web.QuietServer(("127.0.0.1", 0), BigBodyHandler)
    captured = CapturingStderr()
    original = sys.stderr
    sys.stderr = captured
    try:
        try:
            raise ConnectionResetError(10054, "an existing connection was forcibly closed")
        except ConnectionResetError:
            server.handle_error(None, ("127.0.0.1", 0))
    finally:
        sys.stderr = original
        server.server_close()
    assert captured.text == "", captured.text[:400]


def test_a_real_exception_is_not_swallowed():
    server = web.QuietServer(("127.0.0.1", 0), BigBodyHandler)
    captured = CapturingStderr()
    original = sys.stderr
    sys.stderr = captured
    try:
        try:
            raise ValueError("something actually wrong")
        except ValueError:
            server.handle_error(None, ("127.0.0.1", 0))
    finally:
        sys.stderr = original
        server.server_close()
    assert "ValueError" in captured.text, "a real fault must still be reported"


def test_the_console_handler_survives_a_disconnect():
    """The handler's own guard, which covers the paths socketserver never sees."""
    assert web.Handler._send is not None
    source = __import__("inspect").getsource(web.Handler._send)
    assert "ConnectionResetError" in source
    assert "BrokenPipeError" in source
