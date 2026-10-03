"""Feed URLs are fetched over HTTP; a local server keeps the tests offline."""
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from src.aggregator import FeedFetchError, fetch_feed, load_feed_url


@pytest.fixture
def feed_server(tmp_path):
    (tmp_path / "feed.csv").write_text(
        "type,value\nip,198.51.100.23\n", encoding="utf-8"
    )
    (tmp_path / "feed.json").write_text(
        json.dumps([{"type": "domain", "value": "bad.example"}]), encoding="utf-8"
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            name = self.path.lstrip("/").split("?")[0]
            target = tmp_path / name
            if not target.is_file():
                self.send_error(404)
                return
            body = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # keep the test output quiet
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join()


def _closed_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_a_csv_feed_is_fetched_and_parsed(feed_server):
    url = f"{feed_server}/feed.csv"
    result = load_feed_url(url)
    assert result.indicators == [("ip", "198.51.100.23", url)]


def test_a_json_feed_is_fetched_and_parsed(feed_server):
    url = f"{feed_server}/feed.json"
    result = load_feed_url(url)
    assert result.indicators == [("domain", "bad.example", url)]


def test_fetch_returns_the_raw_text(feed_server):
    assert "198.51.100.23" in fetch_feed(f"{feed_server}/feed.csv")


def test_an_unreachable_url_names_the_url():
    url = f"http://127.0.0.1:{_closed_port()}/feed.csv"
    with pytest.raises(FeedFetchError, match="could not retrieve"):
        fetch_feed(url, timeout=1.0)


def test_a_missing_feed_is_a_clear_error(feed_server):
    with pytest.raises(FeedFetchError, match="404"):
        fetch_feed(f"{feed_server}/absent.csv", timeout=2.0)
