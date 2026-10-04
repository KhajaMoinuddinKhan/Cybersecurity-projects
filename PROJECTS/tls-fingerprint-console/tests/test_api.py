"""API + UI tests for the TLS Fingerprint Console.

Uses in-memory fakes that implement the documented store/corpus/rules
interfaces (no MagicMock).  The app is built with create_app(store, corpus)
and an injected fake rules module so the suite is deterministic and does not
depend on sibling modules that land in parallel.
"""

import pytest

from src.app import create_app


# --------------------------------------------------------------------- fakes
class FakeStore:
    """Implements the documented Store interface in memory."""

    def __init__(self):
        self._events = []
        self._alerts = []
        self._fps = {}

    def add_event(self, event):
        event = dict(event)
        self._events.append(event)
        kind = event.get("fingerprint_kind") or event.get("kind")
        value = event.get("fingerprint_value") or event.get("value")
        if kind and value:
            key = (kind, value)
            ts = event.get("ts")
            fp = self._fps.get(key)
            if fp is None:
                self._fps[key] = {
                    "kind": kind,
                    "value": value,
                    "first_seen": ts,
                    "last_seen": ts,
                    "count": 1,
                }
            else:
                fp["count"] += 1
                if ts is not None:
                    if fp["first_seen"] is None or ts < fp["first_seen"]:
                        fp["first_seen"] = ts
                    if fp["last_seen"] is None or ts > fp["last_seen"]:
                        fp["last_seen"] = ts

    def add_alert(self, alert):
        self._alerts.append(dict(alert))

    def events(self):
        return list(self._events)

    def alerts(self):
        return list(self._alerts)

    def fingerprints(self):
        return list(self._fps.values())

    def stats(self):
        return {
            "events": len(self._events),
            "alerts": len(self._alerts),
            "fingerprints": len(self._fps),
        }

    def seen_before(self, kind, value):
        return (kind, value) in self._fps

    def close(self):
        pass


class FakeEntry:
    def __init__(self, kind, value, category, name, source, license):
        self.kind = kind
        self.value = value
        self.category = category
        self.name = name
        self.source = source
        self.license = license


class FakeCorpus:
    """Implements the documented Corpus interface in memory."""

    def __init__(self, entries=None):
        self._entries = list(entries or [])

    def match(self, kind, value):
        for e in self._entries:
            if e.kind == kind and e.value == value:
                return e
        return None

    def entries(self):
        return list(self._entries)

    def stats(self):
        cats = {}
        for e in self._entries:
            cats[e.category] = cats.get(e.category, 0) + 1
        return {
            "sources": sorted({e.source for e in self._entries}),
            "by_category": [{"category": k, "count": v} for k, v in cats.items()],
            "total": len(self._entries),
        }


class FakeRules:
    """Deterministic evaluator: flags events whose ja3 is 'deadbeef'."""

    @staticmethod
    def evaluate(event, ctx):
        if event.get("ja3") == "deadbeef":
            return [
                {
                    "rule": "known_bad",
                    "severity": "high",
                    "title": "Known-bad JA3",
                    "detail": "matches a corpus entry",
                }
            ]
        return []


# --------------------------------------------------------------------- fixtures
def make_corpus():
    return FakeCorpus(
        [
            FakeEntry("ja3", "a1b2c3d4e5f6", "malware", "Tor client", "abuse.ch", "CC0"),
            FakeEntry("ja4", "t13d1516h2_x", "tooling", "curl default", "internal", "CC0"),
            FakeEntry("sni", "gateway.example.net", "infrastructure", "Example Gateway", "internal", "CC0"),
        ]
    )


@pytest.fixture
def store():
    return FakeStore()


@pytest.fixture
def corpus():
    return make_corpus()


@pytest.fixture
def app(store, corpus):
    return create_app(store, corpus, rules_module=FakeRules)


@pytest.fixture
def client(app):
    return app.test_client()


def seed_alert(store, rule, severity, ts, title="t"):
    store.add_alert(
        {
            "rule": rule,
            "severity": severity,
            "title": title,
            "detail": "d",
            "src_ip": "10.0.0.1",
            "ts": ts,
        }
    )


# --------------------------------------------------------------------- tests
def test_health_ok(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_stats_shape(client, store, corpus):
    store.add_event({"ts": 1, "src_ip": "1.1.1.1", "fingerprint_kind": "ja3", "fingerprint_value": "aa"})
    store.add_event({"ts": 2, "src_ip": "1.1.1.2", "fingerprint_kind": "ja3", "fingerprint_value": "bb"})
    seed_alert(store, "known_bad", "high", 1)
    seed_alert(store, "first_seen", "low", 2)

    data = client.get("/api/stats").get_json()
    assert set(data) >= {
        "events",
        "alerts",
        "alerts_by_rule",
        "alerts_by_severity",
        "fingerprints",
        "intel",
    }
    assert data["events"] == 2
    assert data["alerts"] == 2
    assert data["fingerprints"] == 2
    assert isinstance(data["alerts_by_rule"], list)
    assert isinstance(data["alerts_by_severity"], list)
    assert data["intel"]["total"] == 3


def test_alerts_newest_first_and_filtering(client, store):
    seed_alert(store, "known_bad", "high", 100, "older")
    seed_alert(store, "first_seen", "low", 200, "newer")

    all_alerts = client.get("/api/alerts").get_json()["alerts"]
    assert [a["title"] for a in all_alerts] == ["newer", "older"]

    by_rule = client.get("/api/alerts?rule=known_bad").get_json()["alerts"]
    assert len(by_rule) == 1 and by_rule[0]["rule"] == "known_bad"

    by_sev = client.get("/api/alerts?severity=high").get_json()["alerts"]
    assert len(by_sev) == 1 and by_sev[0]["severity"] == "high"

    combo = client.get("/api/alerts?rule=known_bad&severity=low").get_json()["alerts"]
    assert combo == []

    limited = client.get("/api/alerts?limit=1").get_json()["alerts"]
    assert len(limited) == 1 and limited[0]["title"] == "newer"


def test_events_filter_by_sni_and_limit(client, store):
    store.add_event({"ts": 1, "sni": "a.example.net"})
    store.add_event({"ts": 2, "sni": "b.example.org"})
    store.add_event({"ts": 3, "sni": "A.example.net"})

    data = client.get("/api/events?sni=example.net").get_json()
    assert data["count"] == 2

    limited = client.get("/api/events?limit=1").get_json()
    assert limited["count"] == 1 and limited["events"][0]["ts"] == 3


def test_intel_search_hit_and_miss(client):
    hit = client.get("/api/intel/search?q=tor").get_json()
    assert hit["count"] == 1
    assert hit["entries"][0]["value"] == "a1b2c3d4e5f6"

    by_value = client.get("/api/intel/search?q=GATEWAY").get_json()
    assert by_value["count"] == 1

    miss = client.get("/api/intel/search?q=does-not-exist").get_json()
    assert miss["entries"] == []
    assert miss["count"] == 0

    kinded = client.get("/api/intel/search?kind=ja4").get_json()
    assert kinded["count"] == 1 and kinded["entries"][0]["kind"] == "ja4"


def test_intel_search_empty_query_notes_open_corpus(client):
    data = client.get("/api/intel/search").get_json()
    assert data["count"] == 3
    assert data["note"]


def test_intel_endpoint(client):
    data = client.get("/api/intel").get_json()
    assert data["total"] == 3
    assert len(data["sample"]) == 3


def test_ingest_valid_payload(client, store):
    payload = {
        "events": [
            {"ts": 1, "src_ip": "10.0.0.5", "ja3": "deadbeef",
             "fingerprint_kind": "ja3", "fingerprint_value": "deadbeef"},
            {"ts": 2, "src_ip": "10.0.0.6", "ja3": "cafe"},
        ]
    }
    resp = client.post("/api/ingest", json=payload)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body == {"accepted": 2, "alerts": 1}
    assert len(store.events()) == 2
    assert len(store.alerts()) == 1
    assert store.alerts()[0]["rule"] == "known_bad"
    assert store.alerts()[0]["src_ip"] == "10.0.0.5"


def test_ingest_malformed_returns_400_json(client):
    # not JSON at all
    resp = client.post("/api/ingest", data="not json", content_type="application/json")
    assert resp.status_code == 400
    assert "error" in resp.get_json()

    # events not a list
    resp2 = client.post("/api/ingest", json={"events": "nope"})
    assert resp2.status_code == 400
    assert "error" in resp2.get_json()

    # missing key
    resp3 = client.post("/api/ingest", json={})
    assert resp3.status_code == 400
    assert "error" in resp3.get_json()

    # non-object element
    resp4 = client.post("/api/ingest", json={"events": [1, 2]})
    assert resp4.status_code == 400
    assert "error" in resp4.get_json()


def test_unknown_route_404(client):
    resp = client.get("/api/definitely-not-a-route")
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "not found"


def test_scope_defaults_passive_and_is_configurable(app, client):
    data = client.get("/api/scope").get_json()
    assert data["mode"] == "passive"
    assert set(data) >= {"mode", "interface", "capture_file", "note"}

    app.config["CAPTURE_SCOPE"] = {
        "mode": "replay",
        "interface": "eth0",
        "capture_file": "data/samples/demo.pcap",
        "note": "replaying a file",
    }
    data2 = client.get("/api/scope").get_json()
    assert data2["mode"] == "replay"
    assert data2["interface"] == "eth0"
    assert data2["capture_file"] == "data/samples/demo.pcap"


def test_export_json_attachment(client, store):
    store.add_event({"ts": 1, "src_ip": "1.1.1.1"})
    seed_alert(store, "known_bad", "high", 1)
    resp = client.get("/api/export?format=json")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("application/json")
    assert "attachment" in resp.headers["Content-Disposition"]
    assert "filename=" in resp.headers["Content-Disposition"]


def test_export_csv_attachment(client, store):
    store.add_event({"ts": 1, "src_ip": "1.1.1.1"})
    resp = client.get("/api/export?format=csv")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/csv")
    assert "attachment" in resp.headers["Content-Disposition"]


def test_export_bad_format_400(client):
    resp = client.get("/api/export?format=xml")
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_index_renders_console_html_with_nav_labels(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/html")
    html = resp.get_data(as_text=True)
    for label in ["Overview", "Alerts", "Fingerprints", "Intel", "Scope", "Export"]:
        assert label in html, "missing nav label: " + label


def test_index_has_no_reference_branding(client):
    html = client.get("/").get_data(as_text=True).lower()
    for banned in [
        "mkutra",
        "valedictorian",
        "alumni",
        "alert ledger",
        "census",
        "wire-tap",
        "biometric of the handshake",
        "mkultraalumni",
    ]:
        assert banned not in html, "reference branding leaked: " + banned


def test_index_is_self_contained(client):
    html = client.get("/").get_data(as_text=True)
    # no CDN / external asset references
    assert "http://" not in html
    assert "https://" not in html
    assert "<script src" not in html
    assert "<link" not in html
