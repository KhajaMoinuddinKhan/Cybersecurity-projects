"""Tests for src.matcher: confidence-scored matching and diversity stats.

The exact-match and JA3-miss cases run against the *real* shipped corpus
(``data/corpus``).  The shipped corpus is JA3-only, so the JA4 partial-match
cases build a tiny corpus of :class:`src.corpus.Entry` objects -- there is
nothing in ``data/corpus`` to fuzzy-match a JA4 against yet.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.corpus import Corpus, Entry, load_corpus  # noqa: E402
from src.matcher import (  # noqa: E402
    MAX_CANDIDATES,
    diversity,
    match_event,
    match_fingerprint,
)

CORPUS_DIR = os.path.join(ROOT, "data", "corpus")

# A real JA3 from the curated file.
TOR_JA3 = "e7d705a3286e19ea42f587b344ee6865"

# One JA4 entry, used as the reference for the section-scoring cases.
JA4_BASE = "t13d1516h2_8daaf6152771_e5627efa2ab1"


@pytest.fixture(scope="module")
def corpus():
    return load_corpus(CORPUS_DIR)


def ja4_corpus():
    """A one-entry JA4 corpus for exercising the b/c-section scoring."""
    return Corpus([
        Entry(kind="ja4", value=JA4_BASE, category="benign", name="Chrome 119",
              source="unit", license="x"),
    ])


# ------------------------------------------------------------------ exact
def test_exact_ja3_scores_one(corpus):
    r = match_fingerprint("ja3", TOR_JA3, corpus)
    assert r["confidence"] == 1.0
    assert "exact" in r["basis"].lower()
    assert r["match"] is not None
    assert r["match"]["name"] == "Tor client"
    assert r["match"]["category"] == "tool"
    # a positive confidence must always carry at least one candidate
    assert r["candidates"]
    assert r["candidates"][0]["score"] == 1.0
    assert r["candidates"][0]["value"] == TOR_JA3


def test_exact_match_is_case_insensitive(corpus):
    r = match_fingerprint("JA3", "  " + TOR_JA3.upper() + "  ", corpus)
    assert r["confidence"] == 1.0
    assert r["match"]["name"] == "Tor client"


# -------------------------------------------------------------------- miss
def test_unknown_ja4_returns_zero_and_no_candidates(corpus):
    r = match_fingerprint("ja4", "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb", corpus)
    assert r["confidence"] == 0.0
    assert r["candidates"] == []
    assert r["match"] is None
    assert r["basis"]  # explains the miss


def test_ja3_miss_returns_zero_and_invents_no_candidate(corpus):
    r = match_fingerprint("ja3", "00000000000000000000000000000000", corpus)
    assert r["confidence"] == 0.0
    assert r["candidates"] == []
    assert r["match"] is None
    assert "opaque" in r["basis"].lower()


# --------------------------------------------------------- ja4 section score
def test_ja4_shared_cipher_hash_scores_half():
    r = match_fingerprint("ja4", "t13d1715h2_8daaf6152771_111111111111", ja4_corpus())
    assert r["confidence"] == 0.5
    assert r["candidates"], "a positive confidence must carry a candidate"
    assert r["candidates"][0]["value"] == JA4_BASE
    assert r["candidates"][0]["name"] == "Chrome 119"
    assert r["match"]["name"] == "Chrome 119"


def test_ja4_shared_extension_hash_scores_point_four():
    r = match_fingerprint("ja4", "t13d1715h2_999999999999_e5627efa2ab1", ja4_corpus())
    assert r["confidence"] == 0.4
    assert r["candidates"][0]["value"] == JA4_BASE
    assert r["candidates"][0]["name"] == "Chrome 119"


def test_ja4_shared_both_but_different_a_scores_point_eight():
    # same b and c, only the a-section (version/SNI/ALPN) differs
    r = match_fingerprint("ja4", "t13d1715h2_8daaf6152771_e5627efa2ab1", ja4_corpus())
    assert r["confidence"] == 0.8
    assert r["candidates"][0]["value"] == JA4_BASE
    assert r["candidates"][0]["name"] == "Chrome 119"
    assert "a-section" in r["basis"]


def test_ja4s_partial_match_uses_same_sections():
    c = Corpus([
        Entry(kind="ja4s", value="t13d1516h2_1301_aaaaaaaaaaaa", category="benign",
              name="Test Server", source="unit", license="x"),
    ])
    r = match_fingerprint("ja4s", "t13d1715h2_1301_bbbbbbbbbbbb", c)
    assert r["confidence"] == 0.5
    assert r["candidates"][0]["name"] == "Test Server"


def test_no_shared_section_gives_zero():
    r = match_fingerprint("ja4", "t13d1715h2_999999999999_999999999999", ja4_corpus())
    assert r["confidence"] == 0.0
    assert r["candidates"] == []


# ------------------------------------------------------------ candidate list
def test_candidates_capped_at_five_and_sorted_descending():
    entries = [
        Entry(kind="ja4", value="t13d1516h2_8daaf6152771_%012d" % i,
              category="benign", name="C%d" % i, source="unit", license="x")
        for i in range(7)
    ]
    c = Corpus(entries)
    # shares the b-section with all seven, differs in a and c
    r = match_fingerprint("ja4", "t13d1715h2_8daaf6152771_ffffffffffff", c)
    assert len(r["candidates"]) == MAX_CANDIDATES == 5
    scores = [cand["score"] for cand in r["candidates"]]
    assert scores == sorted(scores, reverse=True)


def test_confidence_never_positive_without_candidates(corpus):
    cases = [
        ("ja3", TOR_JA3),
        ("ja3", "00000000000000000000000000000000"),
        ("ja4", "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"),
        ("ja4", "not-a-fingerprint"),
        ("ja4s", "t13d1516h2_1301_aaaaaaaaaaaa"),
    ]
    for kind, value in cases:
        r = match_fingerprint(kind, value, corpus)
        if r["confidence"] > 0.0:
            assert r["candidates"], (kind, value)
        else:
            assert r["candidates"] == [], (kind, value)


# ---------------------------------------------------------------- match_event
def test_match_event_picks_best_across_fingerprints(corpus):
    combined = Corpus(corpus.entries() + [
        Entry(kind="ja4", value=JA4_BASE, category="benign", name="Chrome 119",
              source="unit", license="x"),
    ])
    event = {"src_ip": "10.0.0.1", "fingerprints": {
        "ja3": TOR_JA3,                              # exact -> 1.0
        "ja4": "t13d1715h2_8daaf6152771_e5627efa2ab1",  # 0.8
    }}
    results = match_event(event, combined)
    assert len(results) == 2
    assert results[0]["confidence"] == 1.0
    assert results[0]["kind"] == "ja3"
    assert results[1]["confidence"] == 0.8
    assert results[1]["kind"] == "ja4"
    # the best one is recorded on the event
    assert event["best_match"]["kind"] == "ja3"


def test_match_event_drops_misses(corpus):
    event = {"fingerprints": {"ja3": "00000000000000000000000000000000"}}
    assert match_event(event, corpus) == []


def test_match_event_tolerates_missing_fingerprints(corpus):
    assert match_event({}, corpus) == []
    assert match_event({"fingerprints": {}}, corpus) == []
    assert match_event("not a dict", corpus) == []


# ----------------------------------------------------------------- diversity
def ev(src, ja4=None, **kw):
    fps = {}
    if ja4 is not None:
        fps["ja4"] = ja4
    base = {"src_ip": src, "fingerprints": fps}
    base.update(kw)
    return base


def test_diversity_single_fingerprint_vs_rotating():
    events = [ev("10.0.0.1", JA4_BASE) for _ in range(10)]
    events += [ev("10.0.0.2", "t13d1516h2_%012d_%012d" % (i, i)) for i in range(10)]

    d = diversity(events)
    by_src = {s["src_ip"]: s for s in d["sources"]}

    # one fingerprint every time -> diversity ~0.1, dominant_share 1.0
    assert by_src["10.0.0.1"]["distinct_ja4"] == 1
    assert by_src["10.0.0.1"]["diversity"] == pytest.approx(0.1, abs=0.001)
    assert by_src["10.0.0.1"]["dominant_share"] == pytest.approx(1.0, abs=0.001)

    # a different fingerprint every time -> diversity 1.0, dominant_share 0.1
    assert by_src["10.0.0.2"]["distinct_ja4"] == 10
    assert by_src["10.0.0.2"]["diversity"] == pytest.approx(1.0, abs=0.001)
    assert by_src["10.0.0.2"]["dominant_share"] == pytest.approx(0.1, abs=0.001)

    assert d["shared_fingerprints"] == []
    assert d["totals"]["sources"] == 2
    assert d["totals"]["events"] == 20
    assert d["totals"]["distinct_ja4"] == 11


def test_diversity_shared_fingerprint_appears_with_two_sources():
    events = [
        ev("10.0.0.1", JA4_BASE),
        ev("10.0.0.2", JA4_BASE),
        ev("10.0.0.2", "t13d1516h2_%012d_%012d" % (9, 9)),
    ]
    d = diversity(events)
    assert len(d["shared_fingerprints"]) == 1
    sf = d["shared_fingerprints"][0]
    assert sf["kind"] == "ja4"
    assert sf["value"] == JA4_BASE
    assert sf["sources"] == 2
    assert sf["events"] == 2


def test_diversity_sources_sorted_by_events_descending():
    events = [ev("10.0.0.1", JA4_BASE)]
    events += [ev("10.0.0.2", "t13d1516h2_%012d_%012d" % (i, i)) for i in range(5)]
    d = diversity(events)
    counts = [s["events"] for s in d["sources"]]
    assert counts == sorted(counts, reverse=True)
    assert d["sources"][0]["src_ip"] == "10.0.0.2"


def test_diversity_tolerates_missing_fingerprints_and_src_ip():
    events = [
        {"src_ip": "10.0.0.1"},                       # no fingerprints key
        {"src_ip": "10.0.0.1", "fingerprints": {}},   # empty fingerprints
        {"fingerprints": {"ja4": "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"}},  # no src
        {"src_ip": None, "fingerprints": {"ja4": "x_y_z"}},
        {},                                           # empty event
        "not a dict",                                 # junk
    ]
    d = diversity(events)  # must not raise
    assert d["totals"]["sources"] == 1
    assert len(d["sources"]) == 1
    assert d["sources"][0]["src_ip"] == "10.0.0.1"
    assert d["sources"][0]["distinct_ja4"] == 0
    assert d["sources"][0]["diversity"] == 0.0
    assert d["shared_fingerprints"] == []


def test_diversity_handles_non_list_input():
    d = diversity(None)
    assert d["sources"] == []
    assert d["shared_fingerprints"] == []
    assert d["totals"] == {"sources": 0, "events": 0, "distinct_ja4": 0}
