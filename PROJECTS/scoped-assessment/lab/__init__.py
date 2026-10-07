"""A deliberately vulnerable application, for the assessment to find things in.

It is small and it is written to be found. Nothing here is a mistake: each flaw is
placed, documented and mapped to the CVE whose behaviour it imitates, so that the
report has something real to report and the framework has something real to
measure itself against.

It binds to loopback and refuses to bind anywhere else. That refusal is not a
comment, it is a check -- a deliberately vulnerable server that can be reached from
a network is a liability rather than a lab, and the one thing worse than no test
target is one somebody else can find first.

The flaws are the ones the OWASP guidance and the CVEs below describe:
  * a path traversal that imitates CVE-2021-41773
  * a reflected parameter that is written into the page unescaped, imitating the
    class behind CVE-2018-7600
  * a version banner that claims an old release, so fingerprinting has something
    to recognise
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

__all__ = ["LabServer", "serve", "FLAWS", "BANNER"]

# The version the lab claims. A fingerprinting pass should recognise it and the
# CVE mapping should attach the vulnerabilities that version is known for.
BANNER = "LabApp/1.4.2"

# What is deliberately wrong, and which CVE's behaviour it imitates. The report
# reads this; the scanner is not told it.
FLAWS = (
    {"id": "lab-path-traversal",
     "path": "/files",
     "imitates": "CVE-2021-41773",
     "detail": "the name parameter is joined to a root without being confined to it"},
    {"id": "lab-reflected-input",
     "path": "/search",
     "imitates": "CVE-2018-7600",
     "detail": "the q parameter is written into the page without escaping"},
    {"id": "lab-version-disclosure",
     "path": "/",
     "imitates": None,
     "detail": "the Server header names a version, which is a gift to a fingerprinter"},
)

DOCUMENT_ROOT = Path(__file__).resolve().parent / "root"


class _Handler(BaseHTTPRequestHandler):
    server_version = BANNER
    sys_version = ""

    def log_message(self, *args):        # keep the lab quiet
        pass

    def _send(self, status, body, content_type="text/html; charset=utf-8"):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        route = parsed.path.rstrip("/") or "/"

        if route == "/":
            return self._send(200, "<html><body><h1>LabApp</h1>"
                                   "<p>A deliberately vulnerable application.</p>"
                                   "<form action='/search'><input name='q'></form></body></html>")

        if route == "/search":
            # Flaw: the parameter goes into the page unescaped.
            term = (query.get("q") or [""])[0]
            return self._send(200, "<html><body><h1>Results</h1>"
                                   "<p>You searched for %s</p></body></html>" % term)

        if route == "/files":
            # Flaw: the name is joined to the root and then read, so `../` escapes.
            name = (query.get("name") or [""])[0]
            target = (DOCUMENT_ROOT / name)
            try:
                body = target.read_bytes()
            except OSError:
                return self._send(404, "no such file")
            return self._send(200, body, "application/octet-stream")

        if route == "/health":
            return self._send(200, json.dumps({"ok": True}), "application/json")

        return self._send(404, "not found")


class LabServer:
    """The lab, on loopback only, in a thread."""

    def __init__(self, port: int = 0, host: str = "127.0.0.1"):
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("the lab binds to loopback only; refusing %r" % host)
        self.httpd = ThreadingHTTPServer((host, port), _Handler)
        self.host, self.port = self.httpd.server_address[0], self.httpd.server_address[1]
        self._thread: threading.Thread | None = None

    def start(self) -> "LabServer":
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    @property
    def base_url(self) -> str:
        return "http://%s:%d" % (self.host, self.port)


def serve(port: int = 8099, host: str = "127.0.0.1") -> None:
    DOCUMENT_ROOT.mkdir(parents=True, exist_ok=True)
    server = LabServer(port=port, host=host).start()
    print("the lab is listening on %s and binds to loopback only" % server.base_url)
    try:
        while True:
            import time
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    serve(int(os.environ.get("LAB_PORT") or 8099))
