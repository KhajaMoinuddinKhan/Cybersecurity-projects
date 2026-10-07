"""CPE matching, checked against NVD's own verdicts.

This is the module that turns a search result into a finding, so it is checked the
way the CVSS engine is: against the answer key rather than against itself. The
records in `tests/vectors/nvd_cpe_matches.json` are real `configurations` blocks
from NVD, and `nvd_says_matches` is what NVD's own `cpeName` filter returned for
that CVE and that CPE. The implementation has to reach the same verdict from the
configurations alone.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.cpe import CpeError, compare_versions, matches, parse_cpe

VECTORS = Path(__file__).resolve().parent / "vectors" / "nvd_cpe_matches.json"


def records():
    return json.loads(VECTORS.read_text(encoding="utf-8"))["records"]


def decidable():
    return [r for r in records() if r["decidable_from_configurations"]]


def test_the_answer_key_is_committed_and_is_nvds():
    payload = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert payload["records"]
    assert "nvd.nist.gov" in payload["source"]
    assert len(decidable()) >= 5, "the configurations have to be able to decide something"
    verdicts = {r["affected_per_configurations"] for r in decidable()}
    assert verdicts == {True, False}, "a set that is all one answer proves very little"


def test_the_configurations_and_nvds_filter_are_not_the_same_question():
    """NVD's cpeName filter returns a CVE when the CPE appears anywhere in its
    configuration tree, including as a platform the CVE does not affect.

    CVE-2009-3766 is a mutt vulnerability whose configuration lists OpenSSL as a
    non-vulnerable platform. The filter returns it for an OpenSSL CPE; the
    configurations say OpenSSL is not affected by it. Asking the feed whether a
    product is *mentioned* is a search; asking the configurations whether the
    version is in range is a finding, and conflating them is how a scanner reports
    a product as vulnerable because its name appeared.
    """
    disagreements = [r for r in records()
                     if r["nvd_filter_returned"] != r["affected_per_configurations"]
                     and r["decidable_from_configurations"]]
    assert disagreements, "if these ever agree, this test has stopped meaning anything"
    for record in disagreements:
        assert record["platform_hits"] >= 1, record["cve"]


def test_the_gap_in_the_newer_affected_field_is_visible():
    """NVD is migrating away from CPE configurations, and this reads only the old
    structure. The records it cannot decide are kept rather than dropped."""
    undecidable = [r for r in records() if r["affected_elsewhere"]]
    assert undecidable, "the vector file should still show what this cannot read"


@pytest.mark.parametrize("record", decidable(), ids=lambda r: r["cve"])
def test_every_decidable_record_matches_the_configurations(record):
    """The differential test: decide from the configurations, compare to them."""
    verdict = matches(record["configurations"], parse_cpe(record["cpe"]))
    assert verdict is record["affected_per_configurations"], (
        "%s against %s: decided %s, the configurations say %s"
        % (record["cve"], record["label"], verdict, record["affected_per_configurations"]))


# --- version ordering, which is where a naive comparison goes wrong ---------

@pytest.mark.parametrize("left,right,expected", [
    ("2.4.49", "2.4.50", -1),
    ("2.10", "2.9", 1),            # numeric, not textual: "2.10" > "2.9"
    ("1.2.1", "1.2", 1),           # a longer version sharing a prefix is greater
    ("1.0.2k", "1.0.2", 1),
    ("1.0.2", "1.0.3", -1),
    ("1.0", "1.0", 0),
    ("1.0.2", "1.0.alpha", 1),     # numeric outranks non-numeric at a position
    ("10.0", "9.9", 1),
])
def test_version_ordering(left, right, expected):
    assert compare_versions(left, right) == expected
    assert compare_versions(right, left) == -expected


# --- the pieces ------------------------------------------------------------

def test_a_cpe_round_trips():
    text = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert parse_cpe(text).name == text
    assert parse_cpe(text).product == "http_server"


@pytest.mark.parametrize("bad", ["", "cpe:/a:apache", "cpe:2.2:a:apache:http_server:1:*:*:*:*:*:*:*",
                                 "cpe:2.3:x:apache:http_server:1:*:*:*:*:*:*:*"])
def test_a_string_that_is_not_a_cpe_is_refused(bad):
    with pytest.raises(CpeError):
        parse_cpe(bad)


def test_an_exact_version_matches_only_itself():
    configurations = [{"nodes": [{"operator": "OR", "cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]}]
    assert matches(configurations, parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"))
    assert not matches(configurations, parse_cpe("cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"))


def test_a_version_range_is_honoured():
    """The form that makes "affected" possible rather than "mentioned"."""
    configurations = [{"nodes": [{"operator": "OR", "cpeMatch": [{
        "vulnerable": True,
        "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "2.0.0",
        "versionEndExcluding": "2.4.50",
    }]}]}]
    inside = parse_cpe("cpe:2.3:a:vendor:product:2.4.49:*:*:*:*:*:*:*")
    at_end = parse_cpe("cpe:2.3:a:vendor:product:2.4.50:*:*:*:*:*:*:*")
    before = parse_cpe("cpe:2.3:a:vendor:product:1.9.9:*:*:*:*:*:*:*")
    assert matches(configurations, inside)
    assert not matches(configurations, at_end), "EndExcluding excludes the boundary"
    assert not matches(configurations, before)


def test_an_inclusive_boundary_includes_it():
    configurations = [{"nodes": [{"operator": "OR", "cpeMatch": [{
        "vulnerable": True, "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "1.0", "versionEndIncluding": "2.0"}]}]}]
    assert matches(configurations, parse_cpe("cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*"))
    assert not matches(configurations, parse_cpe("cpe:2.3:a:vendor:product:2.1:*:*:*:*:*:*:*"))


def test_a_criterion_that_is_not_vulnerable_is_not_a_match():
    """NVD lists the unaffected platform in the same block as the affected one."""
    configurations = [{"nodes": [{"operator": "OR", "cpeMatch": [
        {"vulnerable": False, "criteria": "cpe:2.3:o:vendor:os:1:*:*:*:*:*:*:*"}]}]}]
    assert not matches(configurations, parse_cpe("cpe:2.3:o:vendor:os:1:*:*:*:*:*:*:*"))


def test_a_negated_node_inverts():
    configurations = [{"nodes": [{"operator": "OR", "negate": True, "cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*"}]}]}]
    assert not matches(configurations, parse_cpe("cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*"))
    assert matches(configurations, parse_cpe("cpe:2.3:a:vendor:product:2:*:*:*:*:*:*:*"))


def test_an_empty_configuration_matches_nothing():
    assert not matches([], parse_cpe("cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*"))
    assert not matches(None, parse_cpe("cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*"))
