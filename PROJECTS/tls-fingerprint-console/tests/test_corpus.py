import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.corpus import load_corpus  # noqa: E402

CORPUS_DIR = os.path.join(ROOT, "data", "corpus")


@pytest.fixture(scope="module")
def corpus():
    return load_corpus(CORPUS_DIR)


def test_corpus_loads(corpus):
    assert corpus.entries()
    assert len(corpus.entries()) == corpus.stats()["total"]


def test_total_over_200(corpus):
    assert corpus.stats()["total"] > 200


def test_tor_ja3_found_as_tool(corpus):
    e = corpus.match("ja3", "e7d705a3286e19ea42f587b344ee6865")
    assert e is not None
    assert e.category == "tool"
    assert e.name == "Tor client"


def test_trickbot_found_as_malware(corpus):
    e = corpus.match("ja3", "6734f37431670b3ab4292b8f60f29984")
    assert e is not None
    assert e.category == "malware"
    # also the curated Trickbot JA3S
    e2 = corpus.match("ja3s", "623de93db17d313345d7ea481e7443cf")
    assert e2 is not None and e2.category == "malware"


def test_match_is_case_insensitive(corpus):
    e = corpus.match("JA3", "  E7D705A3286E19EA42F587B344EE6865  ")
    assert e is not None and e.category == "tool"


def test_unknown_returns_none(corpus):
    assert corpus.match("ja3", "00000000000000000000000000000000") is None
    assert corpus.match("ja3", "not-a-real-fingerprint") is None


def test_stats_sources_and_licences(corpus):
    stats = corpus.stats()
    by_name = {s["name"]: s for s in stats["sources"]}
    assert "abuse.ch SSLBL" in by_name
    assert by_name["abuse.ch SSLBL"]["license"] == "CC0-1.0"
    assert "salesforce/ja3 osx-nix" in by_name
    assert by_name["salesforce/ja3 osx-nix"]["license"] == "BSD-3-Clause"
    assert "tlsfp curated" in by_name
    assert by_name["tlsfp curated"]["license"] == "project"
    for s in stats["sources"]:
        assert s["records"] > 0
        assert s["kind"]


def test_by_category_sums_to_total(corpus):
    stats = corpus.stats()
    assert sum(c["records"] for c in stats["by_category"]) == stats["total"]


def test_source_records_match_entries(corpus):
    stats = corpus.stats()
    assert sum(s["records"] for s in stats["sources"]) == stats["total"]


def test_malformed_file_is_skipped(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps([
        {"kind": "ja3", "value": "AABBCCDDEEFF00112233445566778899",
         "category": "benign", "name": "test", "source": "unit", "license": "x"}
    ]), encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not valid json ", encoding="utf-8")

    c = load_corpus(str(tmp_path))  # must not raise
    assert c.match("ja3", "aabbccddeeff00112233445566778899") is not None
    assert c.stats()["total"] == 1
    assert c.skipped  # the bad file was noted
    assert any(os.path.basename(s["file"]) == "bad.json" for s in c.skipped)


def test_missing_dir_does_not_raise(tmp_path):
    c = load_corpus(str(tmp_path / "does-not-exist"))
    assert c.stats()["total"] == 0
    assert c.entries() == []
