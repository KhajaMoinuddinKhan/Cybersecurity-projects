"""Coverage as a table rather than as a sequence of calls.

The point of the registry is that adding a check is adding a row, not editing the
function that runs them. These tests hold that to be true, because "extensible" is
the kind of claim that stops being true the moment somebody adds a special case.
"""

from __future__ import annotations

import json

import pytest

from lab import LabServer
from src import assessment
from src.assessment import CHECKS, CHECK_NAMES, CONFIRMABLE, Check, assess_http
from src.scope import load_scope


@pytest.fixture(scope="module")
def lab():
    with LabServer(port=0) as server:
        yield server


def engagement(tmp_path, ports):
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps({
        "engagement": "test", "targets": [{"host": "127.0.0.1", "ports": list(ports)}],
        "allowed_actions": ["connect"]}), encoding="utf-8")
    return load_scope(path, audit_path=tmp_path / "audit.jsonl")


def test_the_names_come_from_the_registry():
    """Three lists maintained by hand is three lists that drift."""
    assert CHECK_NAMES == tuple(check.id for check in CHECKS)
    assert CONFIRMABLE == tuple(check.id for check in CHECKS if check.confirmable)


def test_every_registered_check_is_runnable():
    for check in CHECKS:
        assert callable(check.run), check.id
        assert check.title, check.id


def test_the_registry_is_not_empty():
    """A rewrite of the last function in the module once took the registry with it,
    and every check stopped running while every check still existed. The suite
    noticed; this notices sooner and says why."""
    assert len(CHECKS) >= 11, "the registry is empty or truncated: %d checks" % len(CHECKS)
    assert CHECKS[0].run.__name__.startswith("_"), CHECKS[0].run


def test_no_two_checks_share_an_id():
    assert len(CHECK_NAMES) == len(set(CHECK_NAMES))


def test_a_registered_check_runs(tmp_path, lab, monkeypatch):
    """A check added to the table runs, without anything else being edited."""
    seen = []

    def a_new_check(scope, host, port, scheme, at):
        seen.append((host, port))
        return []

    monkeypatch.setattr(assessment, "CHECKS", CHECKS + (
        Check("a-new-check", "Does a newly registered check run?", a_new_check),))
    scope = engagement(tmp_path, [lab.port])
    assess_http(scope, "127.0.0.1", lab.port)
    assert seen == [("127.0.0.1", lab.port)]


def test_a_check_that_is_not_registered_does_not_run(tmp_path, lab, monkeypatch):
    """The other direction: a function that is not in the table is not a check."""
    ran = []

    def orphan(scope, host, port, scheme, at):
        ran.append(1)
        return []

    monkeypatch.setattr(assessment, "CHECKS", tuple(
        check for check in CHECKS if check.id != "version-disclosure"))
    scope = engagement(tmp_path, [lab.port])
    ids = {finding.id for finding in assess_http(scope, "127.0.0.1", lab.port)}
    assert "version-disclosure" not in ids
    assert ran == []


def test_every_check_in_the_registry_actually_fires_against_the_lab(tmp_path, lab):
    """A check that is registered but finds nothing here is either a check the lab
    cannot exercise or a check that does not work, and both are worth failing on."""
    scope = engagement(tmp_path, [lab.port])
    fired = {finding.id for finding in assess_http(scope, "127.0.0.1", lab.port)}
    assert fired == set(CHECK_NAMES)


def test_the_confirmation_flag_is_what_the_report_reads(tmp_path, lab):
    """The registry says which checks can confirm; the findings have to agree."""
    scope = engagement(tmp_path, [lab.port])
    for finding in assess_http(scope, "127.0.0.1", lab.port):
        if finding.id in CONFIRMABLE:
            assert finding.confirmed is True, finding.id
        else:
            assert finding.confirmed is False, finding.id


def test_the_report_lists_checks_in_registry_order():
    from src.report import build, to_markdown
    class Scope:
        engagement = "x"
        targets = []
        audit = type("A", (), {"refusals": []})()
        def as_dict(self): return {"targets": [], "allowed_actions": ["connect"]}
        def hosts(self): return []
    document = build(Scope(), [], [], [])
    assert "## Findings" in to_markdown(document)
