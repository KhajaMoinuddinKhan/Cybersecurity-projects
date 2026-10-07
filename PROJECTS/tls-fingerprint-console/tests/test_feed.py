"""Tests for the live feed, the capture session and the streaming endpoints.

The feed is what makes the console a live view rather than a snapshot, so these
cover the parts that would silently degrade: a subscriber that misses records,
a session that starts twice, and a stream endpoint that breaks the page when no
capture driver is present.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.app import create_app  # noqa: E402
from src.corpus import load_corpus  # noqa: E402
from src.feed import CaptureSession, LiveFeed  # noqa: E402
from src.store import Store  # noqa: E402

CORPUS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "corpus"
)


# ------------------------------------------------------------------- LiveFeed

def test_feed_publishes_to_a_subscriber():
    feed = LiveFeed()
    q = feed.subscribe()
    feed.publish_event({"sni": "example.com"})
    feed.publish_alert({"rule": "first_seen"})
    first = q.get_nowait()
    second = q.get_nowait()
    assert first["kind"] == "event"
    assert first["item"]["sni"] == "example.com"
    assert second["kind"] == "alert"
    assert first["seq"] < second["seq"], "records must carry a monotonic sequence"


def test_feed_recent_is_newest_last_and_bounded():
    feed = LiveFeed(maxlen=5)
    for i in range(12):
        feed.publish_event({"n": i})
    items = feed.recent(100)
    assert len(items) == 5, "the ring must stay bounded"
    assert [r["item"]["n"] for r in items] == [7, 8, 9, 10, 11]


def test_feed_recent_can_filter_by_kind():
    feed = LiveFeed()
    feed.publish_event({"a": 1})
    feed.publish_alert({"b": 2})
    feed.publish_event({"a": 3})
    assert [r["kind"] for r in feed.recent(10, "event")] == ["event", "event"]
    assert [r["kind"] for r in feed.recent(10, "alert")] == ["alert"]


def test_feed_stats_count_and_rate():
    feed = LiveFeed()
    for _ in range(3):
        feed.publish_event({})
    feed.publish_alert({})
    s = feed.stats()
    assert s["events_total"] == 3
    assert s["alerts_total"] == 1
    assert s["events_held"] == 3
    assert "events_per_minute" in s


def test_feed_unsubscribe_stops_delivery():
    feed = LiveFeed()
    q = feed.subscribe()
    feed.publish_event({"n": 1})
    assert q.get_nowait()["item"]["n"] == 1
    feed.unsubscribe(q)
    feed.publish_event({"n": 2})
    assert q.empty()
    assert feed.subscriber_count == 0


def test_feed_ignores_a_subscriber_that_stops_reading():
    """A stalled browser must not block the capture thread."""
    feed = LiveFeed()
    stalled = feed.subscribe(maxsize=1)
    for i in range(50):
        feed.publish_event({"n": i})       # must not raise or block
    assert feed.stats()["events_total"] == 50
    assert stalled.full(), "the subscriber must actually have stalled, or nothing was tested"
    assert feed.subscriber_count == 1, "a stalled subscriber is still a subscriber"


def test_feed_ignores_non_dict_records():
    feed = LiveFeed()
    feed.publish_event("not a dict")
    feed.publish_alert(None)
    assert feed.stats()["events_total"] == 0


# -------------------------------------------------------------- CaptureSession

def test_session_status_shape_before_any_start(tmp_path):
    store = Store(str(tmp_path / "s.db"))
    session = CaptureSession(store, load_corpus(CORPUS_DIR), LiveFeed())
    s = session.status()
    assert s["running"] is False
    assert "interface" in s and "error" in s


def test_session_start_reports_clearly_when_no_driver(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "s.db"))
    session = CaptureSession(store, load_corpus(CORPUS_DIR), LiveFeed())
    from src import capture as capture_mod
    monkeypatch.setattr(capture_mod, "available", lambda: False)
    ok, message = session.start()
    assert ok is False
    assert "Npcap" in message, "the message must say what to install"


def test_session_stop_is_honest_when_nothing_runs(tmp_path):
    store = Store(str(tmp_path / "s.db"))
    session = CaptureSession(store, load_corpus(CORPUS_DIR), LiveFeed())
    ok, message = session.stop()
    assert ok is False
    assert "no capture" in message.lower()


# ------------------------------------------------------------------- the API

@pytest.fixture()
def client(tmp_path):
    store = Store(str(tmp_path / "api.db"))
    feed = LiveFeed()
    session = CaptureSession(store, load_corpus(CORPUS_DIR), feed)
    app = create_app(store, load_corpus(CORPUS_DIR), feed=feed, session=session)
    app.config.update(TESTING=True)
    return app.test_client(), feed, session


def test_api_feed_returns_items_and_stats(client):
    c, feed, _ = client
    feed.publish_event({"sni": "example.com", "fingerprints": {"ja3": "abc"}})
    d = c.get("/api/feed").get_json()
    assert len(d["items"]) == 1
    assert d["items"][0]["item"]["sni"] == "example.com"
    assert d["stats"]["events_total"] == 1


def test_api_feed_rejects_a_bad_kind(client):
    c, _, _ = client
    assert c.get("/api/feed?kind=bogus").status_code == 400


def test_api_capture_status_is_reported(client):
    c, _, _ = client
    d = c.get("/api/capture/status").get_json()
    assert d["running"] is False


def test_api_capture_start_reports_failure_without_a_driver(client, monkeypatch):
    c, _, _ = client
    from src import capture as capture_mod
    monkeypatch.setattr(capture_mod, "available", lambda: False)
    r = c.post("/api/capture/start", json={})
    assert r.status_code == 409
    body = r.get_json()
    assert body["started"] is False
    assert "Npcap" in body["message"]


def test_api_stream_sends_a_hello_then_published_records(client):
    """The stream must greet the browser, then push what the sensor produces.

    Read straight off the generator: the hello is yielded before the endpoint
    blocks on its queue, so the first chunk is the greeting and the second is
    whatever is published next.
    """
    c, feed, _ = client
    r = c.get("/api/stream", buffered=False)
    assert r.status_code == 200
    assert r.mimetype == "text/event-stream"
    it = r.response
    hello = next(it).decode("utf-8", "replace")
    assert "event: hello" in hello
    assert "capture" in hello, "the greeting must carry the capture state"
    feed.publish_event({"sni": "pushed.example"})
    pushed = next(it).decode("utf-8", "replace")
    assert "pushed.example" in pushed
    it.close()


def test_api_stream_says_so_when_there_is_no_feed(tmp_path):
    store = Store(str(tmp_path / "nofeed.db"))
    app = create_app(store, load_corpus(CORPUS_DIR))
    app.config.update(TESTING=True)
    r = app.test_client().get("/api/stream")
    assert r.status_code == 503
    assert "live feed" in r.get_json()["error"]


def test_page_has_a_live_view(client):
    c, _, _ = client
    html = c.get("/").get_data(as_text=True)
    assert 'data-view="live"' in html
    assert 'id="view-live"' in html
    assert "/api/stream" in html
    for label in ("Overview", "Live", "Alerts", "Fingerprints", "Intel", "Scope", "Export"):
        assert label in html
