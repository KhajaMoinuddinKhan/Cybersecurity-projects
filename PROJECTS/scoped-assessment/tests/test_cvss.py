"""The CVSS engine, checked against NVD's own arithmetic.

A scoring implementation that agrees with its own test vectors has proved only
that it is self-consistent, which is the same trap the cryptography toolkit avoids
by testing against a reference implementation. Here the reference is NVD: the
vectors and scores in `tests/vectors/nvd_cvss31.json` are what NVD publishes, and
this module has to reproduce the scores from the vectors.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.cvss import CvssError, parse_vector, score, severity_of

VECTORS = Path(__file__).resolve().parent / "vectors" / "nvd_cvss31.json"


def nvd_records():
    payload = json.loads(VECTORS.read_text(encoding="utf-8"))
    return payload["records"]


def test_the_nvd_vectors_are_committed_and_are_nvds():
    payload = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert payload["records"], "the vectors must be committed for CI to check against"
    assert "nvd.nist.gov" in payload["source"]
    assert all(record["vector"].startswith("CVSS:3.1/") for record in payload["records"])
    # they have to be a spread, or agreeing with them proves very little
    assert len({record["base_severity"] for record in payload["records"]}) >= 3
    assert any("/S:C/" in record["vector"] for record in payload["records"]), "scope changed"
    assert any("/S:U/" in record["vector"] for record in payload["records"]), "scope unchanged"


@pytest.mark.parametrize("record", nvd_records(), ids=lambda r: r["cve"])
def test_every_nvd_vector_scores_what_nvd_publishes(record):
    """The differential test: compute the score from the vector, compare to NVD."""
    computed = score(record["vector"])
    assert computed.score == pytest.approx(record["base_score"], abs=0.05), (
        "%s: computed %.1f, NVD publishes %.1f" % (record["cve"], computed.score, record["base_score"]))
    assert computed.severity.upper() == record["base_severity"].upper()


def test_the_specifications_own_worked_examples():
    """Four vectors whose scores are stated in the specification's text."""
    assert score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").score == 9.8
    assert score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H").score == 7.8
    assert score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N").score == 4.7
    assert score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").score == 0.0


def test_scope_changed_is_not_the_same_as_scope_unchanged():
    """The branch most implementations get wrong, isolated to one comparison.

    The same metrics under S:U and S:C must not produce the same number, and the
    scope-changed form is not simply the unchanged one scaled.
    """
    unchanged = score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").score
    changed = score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").score
    assert unchanged == 9.8 and changed == 10.0


def test_roundup_keeps_a_value_that_is_already_one_decimal():
    """The specification's Roundup, which a naive ceiling gets wrong.

    A score of exactly 4.0 must stay 4.0. Floating-point ceilings turn it into 4.1,
    and that off-by-one-tenth is the classic CVSS implementation bug.
    """
    from src.cvss import _roundup
    assert _roundup(4.0) == 4.0
    assert _roundup(4.01) == 4.1
    assert _roundup(0.0) == 0.0
    assert _roundup(10.0) == 10.0


def test_zero_impact_scores_zero_whatever_the_exploitability():
    assert score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N").score == 0.0
    assert severity_of(0.0) == "None"


@pytest.mark.parametrize("vector", [
    "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "",
    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H",
])
def test_a_vector_that_is_not_a_v31_base_vector_is_refused(vector):
    with pytest.raises(CvssError):
        score(vector)


def test_temporal_metrics_are_ignored_rather_than_rejected():
    """A CVE published with temporal metrics still has a base vector underneath."""
    metrics = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C")
    assert metrics["AV"] == "N" and "E" not in metrics


def test_severity_bands_are_the_specified_ones():
    assert severity_of(0.0) == "None"
    assert severity_of(0.1) == "Low"
    assert severity_of(3.9) == "Low"
    assert severity_of(4.0) == "Medium"
    assert severity_of(6.9) == "Medium"
    assert severity_of(7.0) == "High"
    assert severity_of(8.9) == "High"
    assert severity_of(9.0) == "Critical"
    assert severity_of(10.0) == "Critical"
