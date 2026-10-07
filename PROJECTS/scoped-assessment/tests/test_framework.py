"""The framework end to end, against the lab it ships with.

These tests start the deliberately vulnerable application on loopback and run a
real engagement against it, because the claim being tested is that the tool works,
not that its parts can be called. A finding is only a finding if a socket was
opened and something came back.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from lab import FLAWS, LabServer
from src.assessment import assess_http
from src.cli import run_engagement
from src.report import SEVERITY_ORDER, build, to_html, to_markdown
from src.scan import fetch, probe_port, scan
from src.scope import load_scope

ENGAGEMENT = Path(__file__).resolve().parent.parent / "examples" / "lab-engagement.yaml"


@pytest.fixture(scope="module")
def lab():
    with LabServer(port=0) as server:
        yield server


def engagement(tmp_path, ports, actions=("connect",), window=None):
    data = {"engagement": "test", "targets": [{"host": "127.0.0.1", "ports": list(ports)}],
            "allowed_actions": list(actions)}
    if window:
        data["window"] = window
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return load_scope(path, audit_path=tmp_path / "audit.jsonl")


# --- the lab itself --------------------------------------------------------

def test_the_lab_refuses_to_bind_anywhere_but_loopback():
    """A deliberately vulnerable server that a network can reach is a liability."""
    from lab import LabServer as Server
    with pytest.raises(ValueError):
        Server(port=0, host="0.0.0.0")


def test_every_flaw_the_lab_claims_is_one_the_checks_look_for():
    from src.assessment import CHECK_NAMES
    declared = {flaw["id"].replace("lab-", "").replace("-disclosure", "-disclosure")
                for flaw in FLAWS}
    for flaw in FLAWS:
        if flaw["imitates"]:
            assert any(name in flaw["id"] or flaw["id"] in "lab-" + name
                       for name in CHECK_NAMES), flaw["id"]


# --- scanning is gated by the engagement ------------------------------------

def test_a_port_the_engagement_does_not_list_is_never_opened(tmp_path, lab):
    scope = engagement(tmp_path, [lab.port + 1])
    service = probe_port(scope, "127.0.0.1", lab.port)
    assert not service.open
    assert "refused by scope" in service.error
    assert len(scope.audit.refusals) == 1


def test_a_permitted_port_is_actually_connected_to(tmp_path, lab):
    scope = engagement(tmp_path, [lab.port])
    service = probe_port(scope, "127.0.0.1", lab.port)
    assert service.open
    assert scope.audit.refusals == []


def test_the_scope_window_stops_a_scan_that_is_too_early(tmp_path, lab):
    now = datetime.now(timezone.utc)
    scope = engagement(tmp_path, [lab.port],
                       window={"start": (now + timedelta(days=1)).isoformat(),
                               "end": (now + timedelta(days=2)).isoformat()})
    service = probe_port(scope, "127.0.0.1", lab.port)
    assert not service.open
    assert "window" in service.error


def test_a_refused_request_says_it_was_refused_rather_than_failing(tmp_path, lab):
    """A refusal and a dead port are different things and belong differently in a
    report; the caller has to be able to tell them apart."""
    scope = engagement(tmp_path, [lab.port + 1])
    response = fetch(scope, "127.0.0.1", lab.port, "/")
    assert response["refused"] is True
    assert "not listed" in response["reason"]


def test_scanning_returns_a_row_for_every_port_asked_about(tmp_path, lab):
    scope = engagement(tmp_path, [lab.port, lab.port + 1])
    services = scan(scope, "127.0.0.1", [lab.port, lab.port + 1])
    assert [s.port for s in services] == [lab.port, lab.port + 1]
    assert services[0].open and not services[1].open


# --- the checks find what the lab planted -----------------------------------

def test_the_checks_find_every_flaw_the_lab_has(tmp_path, lab):
    """The lab plants three; the assessment has to report all three."""
    scope = engagement(tmp_path, [lab.port])
    found = {finding.id for finding in assess_http(scope, "127.0.0.1", lab.port)}
    assert found == {"path-traversal", "reflected-input", "version-disclosure"}


def test_the_traversal_finding_carries_the_bytes_that_prove_it(tmp_path, lab):
    """A finding without evidence is an assertion."""
    scope = engagement(tmp_path, [lab.port])
    findings = {f.id: f for f in assess_http(scope, "127.0.0.1", lab.port)}
    traversal = findings["path-traversal"]
    assert traversal.severity == "High"
    assert traversal.evidence, "it must show what came back"
    assert any("outside the document root" in str(item.get("value", ""))
               for item in traversal.evidence)


def test_the_reflected_input_finding_shows_the_unescaped_probe(tmp_path, lab):
    scope = engagement(tmp_path, [lab.port])
    findings = {f.id: f for f in assess_http(scope, "127.0.0.1", lab.port)}
    evidence = " ".join(str(item.get("value", "")) for item in findings["reflected-input"].evidence)
    assert "zq<\"'>zq" in evidence


def test_the_checks_find_nothing_when_the_engagement_permits_nothing(tmp_path, lab):
    """Refusals must not become findings, or the report would accuse a target of
    something the tool was never allowed to look at."""
    scope = engagement(tmp_path, [lab.port + 1])
    assert assess_http(scope, "127.0.0.1", lab.port) == []


# --- the report ------------------------------------------------------------

def test_an_engagement_against_the_lab_produces_both_formats(tmp_path, lab):
    scope = engagement(tmp_path, [lab.port])
    services = scan(scope, "127.0.0.1", [lab.port])
    findings = assess_http(scope, "127.0.0.1", lab.port)
    document = build(scope, services, findings, scope.audit.refusals)

    markdown = to_markdown(document)
    assert "# Security assessment: test" in markdown
    assert "## Scope" in markdown and "## Findings" in markdown
    assert "## What the tool declined to do" in markdown
    assert "Business impact" in markdown and "Remediation" in markdown

    page = to_html(document)
    assert page.startswith("<!doctype html>")
    # self-contained: a report about a client's security should not call out
    for forbidden in ("http://", "https://", "<script", "<link"):
        assert forbidden not in page, forbidden


def test_the_report_lists_the_refusals_it_made(tmp_path, lab):
    """What the tool declined to do is part of the record of the engagement."""
    scope = engagement(tmp_path, [lab.port + 1])
    services = scan(scope, "127.0.0.1", [lab.port])
    document = build(scope, services, [], scope.audit.refusals)
    assert document["refusal_count"] >= 1
    markdown = to_markdown(document)
    assert "not listed" in markdown


def test_findings_are_ordered_by_severity(tmp_path, lab):
    scope = engagement(tmp_path, [lab.port])
    findings = assess_http(scope, "127.0.0.1", lab.port)
    document = build(scope, [], findings, [])
    severities = [f["severity"] for f in document["findings"]]
    assert severities == sorted(severities, key=SEVERITY_ORDER.index)
    assert severities[0] == "High"


def test_an_engagement_with_nothing_to_report_says_so(tmp_path, lab):
    scope = engagement(tmp_path, [lab.port + 1])
    document = build(scope, [], [], [])
    assert document["total"] == 0
    assert "No findings were recorded" in to_markdown(document)


# --- the command line ------------------------------------------------------

def test_the_cli_runs_an_engagement_and_writes_a_report(tmp_path, lab):
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps({
        "engagement": "cli test",
        "targets": [{"host": "127.0.0.1", "ports": [lab.port]}],
        "allowed_actions": ["connect"],
    }), encoding="utf-8")
    document = run_engagement(path, tmp_path / "out")
    assert (tmp_path / "out" / "report.md").exists()
    assert (tmp_path / "out" / "report.html").exists()
    assert (tmp_path / "out" / "audit.jsonl").exists()
    assert document["total"] >= 3


def test_the_cli_refuses_an_unusable_engagement_file(tmp_path):
    from src.cli import main
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps({"engagement": "x", "targets": []}), encoding="utf-8")
    assert main(["--scope", str(path), "--out", str(tmp_path / "out")]) == 2
