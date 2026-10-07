"""A deliberately vulnerable application, for the assessment to find things in.

It is small and it is written to be found. Nothing here is a mistake: each flaw is
placed, documented and mapped to the CVE whose behaviour it imitates, so that the
report has something real to report and the framework has something real to
measure itself against.

It binds to loopback and refuses to bind anywhere else. That refusal is not a
comment, it is a check -- a deliberately vulnerable server that can be reached from
a network is a liability rather than a lab, and the one thing worse than no test
target is one somebody else can find first.

The pages link to each other, which is the point: a scanner that knows three paths
tests three paths, and a crawler that follows links finds what the application
actually exposes. One of those links is deliberately destructive-looking, so that
the crawler's refusal to follow it can be tested rather than assumed.

The flaws, and what each imitates:

  * a path traversal that reads outside its document root          CVE-2021-41773
  * a parameter written into the page unescaped                    CVE-2018-7600
  * a version banner claiming an old release                       --
  * no security headers on any response                            --
  * a session cookie with no Secure, HttpOnly or SameSite          --
  * a directory listing that shows what is in a folder             --
  * a version-control directory served as files                    --
  * a dotfile served as a file                                     --
  * an HTTP method the server answers that it should not           --
  * a redirect that will go wherever it is told                    CVE-2016-10033 (class)
  * an error page that discloses an absolute path                  --
  * a link whose path says it deletes something                    -- (not a flaw: a
    crawler's restraint is what is being tested)
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

__all__ = ["LabServer", "serve", "FLAWS", "BANNER", "DOCUMENT_ROOT"]

# The version the lab claims. A fingerprinting pass should recognise it and the
# CVE mapping should attach the vulnerabilities that version is known for.
BANNER = "LabApp/1.4.2"

# What is deliberately wrong, and which CVE's behaviour it imitates. The report
# reads this; the scanner is not told it.
FLAWS = (
    {"id": "lab-path-traversal", "path": "/files", "imitates": "CVE-2021-41773",
     "detail": "the name parameter is joined to a root without being confined to it"},
    {"id": "lab-reflected-input", "path": "/search", "imitates": "CVE-2018-7600",
     "detail": "the q parameter is written into the page without escaping"},
    {"id": "lab-version-disclosure", "path": "/", "imitates": None,
     "detail": "the Server header names a version, which is a gift to a fingerprinter"},
    {"id": "lab-missing-security-headers", "path": "/", "imitates": None,
     "detail": "no Content-Security-Policy, X-Frame-Options or X-Content-Type-Options"},
    {"id": "lab-insecure-cookie", "path": "/login", "imitates": None,
     "detail": "a session cookie with no Secure, HttpOnly or SameSite attribute"},
    {"id": "lab-directory-listing", "path": "/uploads/", "imitates": None,
     "detail": "the folder's contents are listed to anyone who asks"},
    {"id": "lab-vcs-exposed", "path": "/.git/HEAD", "imitates": None,
     "detail": "the version-control directory is served as ordinary files"},
    {"id": "lab-dotfile-exposed", "path": "/.env", "imitates": None,
     "detail": "a dotfile carrying configuration is served as an ordinary file"},
    {"id": "lab-dangerous-method", "path": "/", "imitates": None,
     "detail": "the server answers TRACE, which it has no reason to"},
    {"id": "lab-open-redirect", "path": "/redirect", "imitates": "CVE-2016-10033",
     "detail": "the to parameter is used as the destination without being checked"},
    {"id": "lab-error-disclosure", "path": "/boom", "imitates": None,
     "detail": "an unhandled error returns an absolute path from the server's disk"},
    {"id": "lab-state-changing-link", "path": "/logout", "imitates": None,
     "detail": "a link that would change state; the crawler must not follow it"},
    {"id": "lab-js-built-link", "path": "/api/reports", "imitates": None,
     "detail": "reached only from a path assembled inside a script, so a crawler "
               "that reads only <a href> cannot see it"},
    {"id": "lab-declared-path", "path": "/internal/status", "imitates": None,
     "detail": "declared in robots.txt and linked from nowhere"},
)

DOCUMENT_ROOT = Path(__file__).resolve().parent / "root"

# Served from the filesystem root of the lab, so a traversal has somewhere to go.
OUTSIDE = Path(__file__).resolve().parent

# A file outside the document root, so a traversal has something to reach that a
# legitimate request could not. The scanner is not told its contents.
_OUTSIDE_FILE = "a file that lives outside the document root\n"


class _Handler(BaseHTTPRequestHandler):
    server_version = BANNER
    sys_version = ""

    def log_message(self, *args):        # keep the lab quiet
        pass

    def _send(self, status, body, content_type="text/html; charset=utf-8", extra_headers=None):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        # Flaw: no Content-Security-Policy, no X-Frame-Options and no
        # X-Content-Type-Options are ever sent. Nothing is added here on purpose.
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # The client went away before the response finished. That is not a failure
            # of this server: a browser that navigates away, a health check that times
            # out and a scanner that closes early all look like this, and letting it
            # reach socketserver means every one of them prints a full traceback --
            # noise that hides the errors that matter.
            self.close_connection = True


    def _page(self, title, body):
        """Every page links to the others, so a crawl has a graph to walk.

        The reports path is deliberately reachable only from inside a script, so a
        crawler that reads only `<a href>` cannot find it and one that reads the
        script can.
        """
        return ("<html><body><h1>%s</h1>%s"
                "<nav><a href='/'>home</a> <a href='/search?q=hello'>search</a> "
                "<a href='/uploads/'>uploads</a> <a href='/login'>sign in</a> "
                "<a href='/redirect?to=/'>a redirect</a> "
                "<a href='/logout'>sign out</a></nav>"
                "<script>var reports = \"/api/reports\";</script>"
                "</body></html>" % (title, body))

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        route = parsed.path.rstrip("/") or "/"

        if route == "/":
            return self._send(200, self._page(
                "LabApp", "<p>A deliberately vulnerable application.</p>"
                          "<form action='/search'><input name='q'></form>"))

        if route == "/search":
            # Flaw: the parameter goes into the page unescaped.
            term = (query.get("q") or [""])[0]
            return self._send(200, self._page("Results", "<p>You searched for %s</p>" % term))

        if route == "/files":
            # Flaw: the name is joined to the root and then read, so `../` escapes.
            name = (query.get("name") or [""])[0]
            target = (DOCUMENT_ROOT / name)
            try:
                body = target.read_bytes()
            except OSError:
                return self._send(404, "no such file")
            return self._send(200, body, "application/octet-stream")

        if route == "/login":
            # Flaw: the session cookie carries no Secure, HttpOnly or SameSite.
            return self._send(
                200, self._page("Sign in", "<form action='/login' method='post'>"
                                           "<input name='user'><input name='pass' type='password'>"
                                           "</form>"),
                extra_headers={"Set-Cookie": "session=abc123; Path=/"})

        if route == "/uploads":
            # Flaw: a directory listing, and the folder is inside the document root.
            folder = DOCUMENT_ROOT / "uploads"
            folder.mkdir(parents=True, exist_ok=True)
            entries = "".join("<li><a href='/uploads/%s'>%s</a></li>" % (quote(n), n)
                              for n in sorted(p.name for p in folder.iterdir()))
            return self._send(200, self._page(
                "Index of /uploads/", "<ul>%s</ul>" % entries))

        if route.startswith("/uploads/"):
            name = parsed.path[len("/uploads/"):]
            target = DOCUMENT_ROOT / "uploads" / name
            if target.is_file():
                return self._send(200, target.read_bytes(), "application/octet-stream")
            return self._send(404, "not found")

        if route == "/.git/HEAD":
            # Flaw: version control served as files. A real repository here would
            # let the whole history be reconstructed from outside.
            return self._send(200, "ref: refs/heads/main\n", "text/plain")

        if route == "/.env":
            # Flaw: configuration served as a file. The value is a placeholder,
            # because a lab that shipped a working credential would be a different
            # kind of problem.
            return self._send(200, "APP_ENV=lab\nAPP_KEY=placeholder-not-a-secret\n"
                                   "DB_PASSWORD=placeholder-not-a-secret\n", "text/plain")

        if route == "/redirect":
            # Flaw: the destination is taken from the request and used unchecked.
            destination = (query.get("to") or ["/"])[0]
            self.send_response(302)
            self.send_header("Location", destination)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if route == "/boom":
            # Flaw: the error names a path on the server's disk.
            return self._send(500, self._page(
                "Error", "<pre>Traceback (most recent call last):\n"
                         "  File \"%s\", line 42, in handle\n"
                         "    raise RuntimeError('deliberate')\n"
                         "RuntimeError: deliberate</pre>" % (OUTSIDE / "app.py")))

        if route == "/logout":
            # Not a flaw: this is what the crawler must refuse to follow. It does
            # nothing, because a lab that actually logged you out would be testing
            # the crawler by breaking something.
            return self._send(200, self._page("Signed out", "<p>You are signed out.</p>"))

        if route == "/api/reports":
            # Not a flaw: this exists so the crawler's ability to see a path built
            # inside a script can be tested rather than assumed.
            return self._send(200, self._page(
                "Reports", "<p>Only reachable if the crawl read the script.</p>"))

        if route == "/internal/status":
            # Not a flaw: declared in robots.txt and linked from nowhere.
            return self._send(200, json.dumps({"status": "internal"}), "application/json")

        if route == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /internal/status\n"
                                   "Disallow: /uploads/\n", "text/plain")

        if route == "/health":
            return self._send(200, json.dumps({"ok": True}), "application/json")

        return self._send(404, "not found")

    def do_TRACE(self):
        # Flaw: TRACE is answered, and it echoes the request back.
        self._send(200, "TRACE %s" % self.path, "message/http")

    def do_HEAD(self):
        self._send(200, b"", "text/html")


class LabServer:
    """The lab, on loopback only, in a thread."""

    def __init__(self, port: int = 0, host: str = "127.0.0.1"):
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("the lab binds to loopback only; refusing %r" % host)
        _prepare_files()
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


def _prepare_files() -> None:
    """Put the files the flaws need in place, if they are not already there."""
    DOCUMENT_ROOT.mkdir(parents=True, exist_ok=True)
    (DOCUMENT_ROOT / "uploads").mkdir(parents=True, exist_ok=True)
    (DOCUMENT_ROOT / "index.html").write_text(
        "<html><body><h1>LabApp</h1></body></html>", encoding="utf-8")
    (DOCUMENT_ROOT / "uploads" / "notes.txt").write_text(
        "A file in a folder that should not be listed.\n", encoding="utf-8")
    # Outside the document root, so a traversal has something to reach that a
    # legitimate request could not.
    (OUTSIDE / "secret.txt").write_text(_OUTSIDE_FILE, encoding="utf-8")


def serve(port: int = 8099, host: str = "127.0.0.1") -> None:
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
