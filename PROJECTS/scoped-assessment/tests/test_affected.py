"""The newer `affected` structure, checked against NVD's own data.

NVD is migrating away from CPE configurations, and a tool that reads only the old
structure answers "not affected" for every CVE published in the new form. That is a
quiet false negative, which is the worst failure mode available to something whose
job is to tell you what is wrong: it looks exactly like good news.

The records here are real `affected` blocks for two CVEs with genuine version
ranges, and the expected verdicts are NVD's own.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.cpe import affected_matches, parse_cpe, verdict

VECTORS = Path(__file__).resolve().parent / "vectors" / "nvd_affected_matches.json"


def records():
    return json.loads(VECTORS.read_text(encoding="utf-8"))["records"]


def test_the_answer_key_is_committed_and_is_nvds():
    payload = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert "nvd.nist.gov" in payload["source"]
    verdicts = {r["affected_per_affected_block"] for r in payload["records"]}
    assert verdicts == {True, False}, "a set that is all one answer proves very little"


@pytest.mark.parametrize("record", records(), ids=lambda r: "%s-%s" % (r["cve"], r["why"][:24]))
def test_every_record_matches_the_affected_block(record):
    decided = affected_matches(record["affected"], parse_cpe(record["cpe"]))
    assert decided is record["affected_per_affected_block"], (
        "%s (%s): decided %s, NVD says %s"
        % (record["cve"], record["why"], decided, record["affected_per_affected_block"]))


def test_a_version_range_stops_where_nvd_says_it_stops():
    """The boundary is the whole point of a range: 10.2.8 is affected and 10.2.9-h1
    is the fix, and a comparison that got the exclusive bound wrong would report
    the patched version as vulnerable."""
    block = [r for r in records() if r["cve"] == "CVE-2024-3400"][0]["affected"]
    assert affected_matches(block, parse_cpe("cpe:2.3:o:paloaltonetworks:pan-os:10.2.8:*:*:*:*:*:*:*"))
    assert not affected_matches(block, parse_cpe("cpe:2.3:o:paloaltonetworks:pan-os:10.2.9-h1:*:*:*:*:*:*:*"))


def test_a_vendor_spelled_two_ways_is_the_same_vendor():
    """NVD writes "Palo Alto Networks" in one structure and `paloaltonetworks` in
    the other. A comparison that only collapsed spaces would miss every product
    whose name has more than one word, which is most of them."""
    block = [r for r in records() if r["cve"] == "CVE-2024-3400"][0]["affected"]
    assert affected_matches(block, parse_cpe("cpe:2.3:o:paloaltonetworks:pan-os:10.2.0:*:*:*:*:*:*:*"))


def test_a_block_with_no_usable_data_is_not_a_verdict_of_no():
    """NVD publishes `n/a` for the vendor, the product and the version on older
    CVEs. "Nobody has said" and "this does not affect you" are different answers
    and a report that treats them the same is guessing."""
    block = [{"source": "cve@mitre.org", "affectedData": [
        {"vendor": "n/a", "product": "n/a",
         "versions": [{"version": "n/a", "status": "affected"}]}]}]
    assert affected_matches(block, parse_cpe("cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*")) is None


def test_an_empty_block_is_not_a_verdict_of_no():
    assert affected_matches([], parse_cpe("cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*")) is None
    assert affected_matches(None, parse_cpe("cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*")) is None


def test_a_product_that_is_not_named_is_not_affected():
    block = [{"affectedData": [{"vendor": "somebody", "product": "else", "versions": [
        {"version": "0", "status": "affected"}]}]}]
    assert affected_matches(block, parse_cpe("cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*")) is False


# --- the combined verdict --------------------------------------------------

def test_the_verdict_says_which_structure_decided():
    """A tool that says "not affected" has to be able to say which data it read to
    conclude that."""
    record = [r for r in records() if r["cve"] == "CVE-2024-3400"][0]
    target = parse_cpe(record["cpe"])
    result = verdict(record["configurations"], record["affected"], target)
    assert result["affected"] is True
    assert result["source"] in ("configurations", "affected")


def test_a_cve_with_neither_structure_is_reported_as_unanswered():
    result = verdict(None, None, parse_cpe("cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*"))
    assert result["affected"] is None
    assert result["source"] == "none"


def test_the_affected_structure_can_carry_a_verdict_the_configurations_cannot():
    """This is the gap the whole module exists to close: a CVE whose only affected
    data is in the new structure used to read as "not affected"."""
    record = [r for r in records() if r["cve"] == "CVE-2024-3400"][0]
    target = parse_cpe(record["cpe"])
    from_configurations = (record["configurations"] is not None
                           and any(n.get("cpeMatch") for c in (record["configurations"] or [])
                                   for n in c.get("nodes") or []))
    result = verdict(record["configurations"], record["affected"], target)
    if not from_configurations:
        assert result["source"] == "affected", result
