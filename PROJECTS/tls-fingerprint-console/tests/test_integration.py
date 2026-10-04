"""End-to-end tests over the real store, corpus, rules and app.

These exist because the first integration had two defects that every unit
suite was blind to: /api/ingest stored the event before evaluating the rules,
so first_seen could never fire, and the app never supplied os_by_ja3, so
os_mismatch could never fire.  Unit tests on isolated rules cannot catch
either, so these drive the real objects through the real endpoint.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import rules as rules_module
from src.app import create_app
from src.corpus import load_corpus
from src.store import Store

CORPUS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "corpus"
)

# A JA3 that the bundled salesforce OSX/*nix list contains, so os_by_ja3 maps
# it to the unix family.
UNIX_JA3 = "61d50e7771aee7f2f4b89a7200b4d45e"


@pytest.fixture()
def wired(tmp_path):
    store = Store(str(tmp_path / "console.db"))
    corpus = load_corpus(CORPUS_DIR)
    app = create_app(store, corpus, rules_module=rules_module)
    app.config.update(TESTING=True)
    return app.test_client(), store, corpus


def _event(**kw):
    base = {
        "ts": 1000.0,
        "src_ip": "10.0.0.5",
        "dst_ip": "93.184.216.34",
        "src_port": 51000,
        "dst_port": 443,
        "sni": "example.com",
        "alpn": "h2",
        "user_agent": None,
        "fingerprints": {"ja3": UNIX_JA3, "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"},
    }
    base.update(kw)
    return base


def test_first_seen_fires_through_the_api(wired):
    client, store, _ = wired
    r = client.post("/api/ingest", json={"events": [_event()]})
    assert r.status_code == 200
    assert r.get_json()["accepted"] == 1
    fired = [a["rule"] for a in store.alerts()]
    assert "first_seen" in fired, "first_seen must fire on a genuinely new fingerprint"


def test_first_seen_does_not_refire_for_a_known_fingerprint(wired):
    client, store, _ = wired
    client.post("/api/ingest", json={"events": [_event()]})
    before = len([a for a in store.alerts() if a["rule"] == "first_seen"])
    client.post("/api/ingest", json={"events": [_event(ts=1001.0)]})
    after = len([a for a in store.alerts() if a["rule"] == "first_seen"])
    assert before >= 1
    assert after == before, "a fingerprint seen before must not alert again"


def test_os_mismatch_fires_when_a_unix_stack_claims_windows(wired):
    client, store, _ = wired
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0"
    client.post("/api/ingest", json={"events": [_event(user_agent=ua)]})
    fired = [a for a in store.alerts() if a["rule"] == "os_mismatch"]
    assert fired, "a unix-family JA3 behind a Windows User-Agent is a real mismatch"
    assert "windows" in fired[0]["detail"].lower()


def test_os_mismatch_stays_quiet_for_a_unix_stack_claiming_macos(wired):
    client, store, _ = wired
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    client.post("/api/ingest", json={"events": [_event(user_agent=ua)]})
    assert not [a for a in store.alerts() if a["rule"] == "os_mismatch"], (
        "macOS and Linux share TLS stacks; the rule must not invent a mismatch"
    )


def test_known_bad_fires_for_a_real_malware_fingerprint(wired):
    client, store, corpus = wired
    entry = next(e for e in corpus.entries() if e.category == "malware" and e.kind == "ja3")
    client.post("/api/ingest", json={"events": [_event(fingerprints={"ja3": entry.value})]})
    fired = [a for a in store.alerts() if a["rule"] == "known_bad"]
    assert fired, "a fingerprint on the malware list must raise known_bad"
    assert fired[0]["severity"] == "critical"


def test_fp_rotation_fires_across_several_events(wired):
    client, store, _ = wired
    events = [
        _event(ts=2000.0 + i, fingerprints={"ja3": UNIX_JA3, "ja4": "t13d1516h2_%s_%s" % (i, i)})
        for i in range(3)
    ]
    client.post("/api/ingest", json={"events": events})
    assert [a for a in store.alerts() if a["rule"] == "fp_rotation"], (
        "three distinct JA4s from one IP and one SNI is rotation"
    )


def test_monoculture_fires_across_many_ips(wired):
    client, store, _ = wired
    events = [
        _event(ts=3000.0 + i, src_ip="10.0.0.%d" % (10 + i),
               fingerprints={"ja3": UNIX_JA3, "ja4": "t13d1516h2_aaaa_bbbb"})
        for i in range(10)
    ]
    client.post("/api/ingest", json={"events": events})
    assert [a for a in store.alerts() if a["rule"] == "monoculture"], (
        "one fingerprint from ten hosts is a monoculture"
    )


def test_every_rule_in_the_module_is_reachable_through_the_app(wired):
    """No rule may be dead: each must be able to fire from the real endpoint."""
    client, store, corpus = wired
    mal = next(e for e in corpus.entries() if e.category == "malware" and e.kind == "ja3")
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0"
    events = [_event(ts=4000.0, user_agent=ua, fingerprints={"ja3": mal.value})]
    events += [
        _event(ts=4001.0 + i, fingerprints={"ja3": UNIX_JA3, "ja4": "t13d1516h2_%s_%s" % (i, i)})
        for i in range(3)
    ]
    events += [
        _event(ts=5000.0 + i, src_ip="10.1.0.%d" % (10 + i),
               fingerprints={"ja3": UNIX_JA3, "ja4": "t13d1516h2_cccc_dddd"})
        for i in range(10)
    ]
    client.post("/api/ingest", json={"events": events})
    fired = {a["rule"] for a in store.alerts()}
    for rule in ("known_bad", "first_seen", "fp_rotation", "monoculture"):
        assert rule in fired, "rule %r never fired through the app" % rule
