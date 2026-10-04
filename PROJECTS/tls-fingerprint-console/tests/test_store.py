import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.store import Store  # noqa: E402


@pytest.fixture
def store():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    s = Store(path)
    try:
        yield s
    finally:
        s.close()
        try:
            os.remove(path)
        except OSError:
            pass


def test_event_roundtrip(store):
    store.add_event({
        "ts": 1.0, "src_ip": "10.0.0.1", "dst_ip": "1.1.1.1",
        "src_port": 50000, "dst_port": 443, "sni": "x.com", "alpn": "h2",
        "user_agent": "curl/8", "category": "benign", "intel_name": None,
        "fingerprints": {"ja3": "abc", "ja4": "j4"},
    })
    events = store.events()
    assert len(events) == 1
    got = events[0]
    assert got["src_ip"] == "10.0.0.1"
    assert got["sni"] == "x.com"
    assert got["user_agent"] == "curl/8"
    assert got["fingerprints"]["ja3"] == "abc"
    assert got["fingerprints"]["ja4"] == "j4"


def test_seen_before_false_then_true(store):
    assert store.seen_before("ja3", "abc") is False
    store.add_event({"ts": 1.0, "src_ip": "a", "fingerprints": {"ja3": "abc"}})
    assert store.seen_before("ja3", "abc") is True
    assert store.seen_before("ja3", "zzz") is False
    assert store.seen_before("ja4", "abc") is False


def test_fingerprints_are_maintained_on_insert(store):
    store.add_event({"ts": 1.0, "src_ip": "a", "fingerprints": {"ja4": "j"}})
    store.add_event({"ts": 2.0, "src_ip": "b", "fingerprints": {"ja4": "j"}})
    fps = store.fingerprints()
    assert len(fps) == 1
    row = fps[0]
    assert row["kind"] == "ja4"
    assert row["value"] == "j"
    assert row["count"] == 2
    assert row["first_seen"] == 1.0
    assert row["last_seen"] == 2.0


def test_alerts_roundtrip(store):
    store.add_alert({
        "ts": 5.0, "rule": "known_bad", "severity": "critical",
        "title": "known-bad fingerprint", "detail": "d",
        "src_ip": "10.0.0.1", "fp_kind": "ja3", "fp_value": "abc",
    })
    alerts = store.alerts()
    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule"] == "known_bad"
    assert a["severity"] == "critical"
    assert a["src_ip"] == "10.0.0.1"
    assert a["fp_kind"] == "ja3" and a["fp_value"] == "abc"


def test_stats_counts(store):
    store.add_event({"ts": 1.0, "src_ip": "a", "fingerprints": {"ja3": "abc"}})
    store.add_event({"ts": 2.0, "src_ip": "b", "fingerprints": {"ja3": "def"}})
    store.add_alert({"ts": 3.0, "rule": "known_bad", "severity": "critical", "title": "t", "detail": "d"})
    store.add_alert({"ts": 4.0, "rule": "known_bad", "severity": "critical", "title": "t", "detail": "d"})
    store.add_alert({"ts": 5.0, "rule": "monoculture", "severity": "medium", "title": "t", "detail": "d"})

    st = store.stats()
    assert st["events"] == 2
    assert st["alerts"] == 3
    assert st["fingerprints"] == 2

    by_rule = {d["rule"]: d["count"] for d in st["alerts_by_rule"]}
    assert by_rule == {"known_bad": 2, "monoculture": 1}

    by_sev = {d["severity"]: d["count"] for d in st["alerts_by_severity"]}
    assert by_sev == {"critical": 2, "medium": 1}

    assert st["top_fingerprints"]
    assert all({"kind", "value", "count"} <= set(t) for t in st["top_fingerprints"])


def test_stats_top_fingerprints_ordered_by_count(store):
    for i in range(3):
        store.add_event({"ts": float(i), "src_ip": "a", "fingerprints": {"ja3": "hot"}})
    store.add_event({"ts": 9.0, "src_ip": "b", "fingerprints": {"ja3": "cold"}})
    top = store.stats()["top_fingerprints"]
    assert top[0]["value"] == "hot"
    assert top[0]["count"] == 3


def test_malformed_event_does_not_raise(store):
    store.add_event({})                      # no keys at all
    store.add_event({"ts": None, "fingerprints": None})
    store.add_event("not-a-dict")
    store.add_alert({})                      # no keys
    store.add_alert("not-a-dict")
    assert len(store.events()) == 3
    assert len(store.alerts()) == 2
    assert store.seen_before("ja3", "x") is False


def test_duplicate_fingerprint_kinds_only_count_once_per_event(store):
    store.add_event({"ts": 1.0, "src_ip": "a",
                     "fingerprints": {"ja3": "same", "ja4": "other"}})
    store.add_event({"ts": 2.0, "src_ip": "b",
                     "fingerprints": {"ja3": "same", "ja4": "other"}})
    fps = {(r["kind"], r["value"]): r["count"] for r in store.fingerprints()}
    assert fps[("ja3", "same")] == 2
    assert fps[("ja4", "other")] == 2
    assert len(fps) == 2


def test_context_manager_closes(tmp_path):
    path = str(tmp_path / "ctx.db")
    with Store(path) as s:
        s.add_event({"ts": 1.0, "src_ip": "a", "fingerprints": {"ja3": "x"}})
        assert s.stats()["events"] == 1
