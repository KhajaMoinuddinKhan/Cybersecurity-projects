"""The scope engine, which is the point of the project.

Every other module asks this one before it touches a socket, so what is tested here
is not that a function returns a boolean but that the defaults refuse, that a
refusal is recorded, and that the ways a scope file can be bent -- a host name that
resolves elsewhere, a port that is nearly listed, a moment a second outside the
window -- do not get through.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from src.scope import AuditLog, Scope, ScopeError, load_scope


def make(tmp_path, **overrides):
    """A minimal engagement, with any field replaced by the caller."""
    data = {
        "engagement": "unit test",
        "targets": [{"host": "127.0.0.1", "ports": [8080]}],
        "allowed_actions": ["connect", "banner"],
    }
    data.update(overrides)
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return load_scope(path, audit_path=tmp_path / "audit.jsonl")


# --- the defaults refuse ---------------------------------------------------

def test_an_engagement_with_no_targets_permits_nothing(tmp_path):
    scope = make(tmp_path, targets=[])
    assert not scope.authorize("127.0.0.1", 8080, "connect")


def test_a_host_the_engagement_does_not_name_is_refused(tmp_path):
    scope = make(tmp_path)
    decision = scope.authorize("127.0.0.2", 8080, "connect")
    assert not decision.allowed
    assert "not within any target" in decision.reason


def test_a_port_the_engagement_does_not_list_is_refused(tmp_path):
    scope = make(tmp_path)
    assert not scope.authorize("127.0.0.1", 8081, "connect")
    assert scope.authorize("127.0.0.1", 8080, "connect")


def test_an_action_the_engagement_does_not_allow_is_refused(tmp_path):
    """Listing targets is not permission to do anything to them."""
    scope = make(tmp_path)
    decision = scope.authorize("127.0.0.1", 8080, "exploit")
    assert not decision.allowed
    assert "not in the engagement's allowed actions" in decision.reason


def test_a_host_name_is_refused_even_if_it_resolves_inside(tmp_path):
    """Only literals. A name can be repointed after the scope file was written.

    A scope engine that resolves names is a scope engine that can be aimed at
    something the engagement never named, which makes the file a suggestion.
    """
    scope = make(tmp_path, targets=[{"host": "localhost", "ports": [8080]}])
    assert not scope.authorize("localhost", 8080, "connect")
    assert not scope.authorize("127.0.0.1", 8080, "connect")


# --- the window ------------------------------------------------------------

def test_a_moment_before_the_window_is_refused(tmp_path):
    now = datetime.now(timezone.utc)
    scope = make(tmp_path, window={"start": (now + timedelta(hours=1)).isoformat(),
                                   "end": (now + timedelta(hours=2)).isoformat()})
    decision = scope.authorize("127.0.0.1", 8080, "connect", at=now)
    assert not decision.allowed
    assert "window" in decision.reason


def test_a_moment_after_the_window_is_refused(tmp_path):
    now = datetime.now(timezone.utc)
    scope = make(tmp_path, window={"start": (now - timedelta(hours=2)).isoformat(),
                                   "end": (now - timedelta(hours=1)).isoformat()})
    assert not scope.authorize("127.0.0.1", 8080, "connect", at=now)


def test_inside_the_window_is_permitted(tmp_path):
    now = datetime.now(timezone.utc)
    scope = make(tmp_path, window={"start": (now - timedelta(hours=1)).isoformat(),
                                   "end": (now + timedelta(hours=1)).isoformat()})
    assert scope.authorize("127.0.0.1", 8080, "connect", at=now)


def test_an_engagement_with_no_window_is_not_time_limited(tmp_path):
    """Absent means unlimited here, and only here, because it is the one field
    whose absence cannot widen what is reachable -- it only widens when."""
    scope = make(tmp_path)
    assert scope.window_start is None and scope.window_end is None
    assert scope.authorize("127.0.0.1", 8080, "connect")


# --- networks and port sets ------------------------------------------------

def test_a_cidr_permits_its_members_and_nothing_else(tmp_path):
    scope = make(tmp_path, targets=[{"cidr": "127.0.0.0/30", "ports": [80]}])
    assert scope.authorize("127.0.0.1", 80, "connect")
    assert scope.authorize("127.0.0.2", 80, "connect")
    assert not scope.authorize("127.0.0.5", 80, "connect")


def test_a_target_may_limit_the_ports_and_another_may_not(tmp_path):
    scope = make(tmp_path, targets=[
        {"host": "127.0.0.1", "ports": [8080]},
        {"host": "127.0.0.2"},
    ])
    assert scope.authorize("127.0.0.1", 8080, "connect")
    assert not scope.authorize("127.0.0.1", 9090, "connect")
    assert scope.authorize("127.0.0.2", 9090, "connect")


def test_a_port_limit_of_all_permits_any_port(tmp_path):
    scope = make(tmp_path, targets=[{"host": "127.0.0.1", "ports": "all"}])
    assert scope.authorize("127.0.0.1", 12345, "connect")


def test_authorising_a_host_without_a_port_asks_only_about_the_host(tmp_path):
    scope = make(tmp_path)
    assert scope.authorize("127.0.0.1", None, "connect")
    assert not scope.authorize("127.0.0.9", None, "connect")


# --- the audit log ---------------------------------------------------------

def test_every_decision_is_recorded_including_the_refusals(tmp_path):
    """A refusal that is not written down is indistinguishable from an action
    that never happened, and the record of what a tool declined to do is the part
    a client asks to see."""
    scope = make(tmp_path)
    scope.authorize("127.0.0.1", 8080, "connect")
    scope.authorize("127.0.0.9", 8080, "connect")
    scope.authorize("127.0.0.1", 8081, "connect")
    assert len(scope.audit.entries) == 3
    assert len(scope.audit.refusals) == 2
    assert {entry["allowed"] for entry in scope.audit.entries} == {True, False}


def test_the_audit_log_is_on_disk_the_moment_it_is_written(tmp_path):
    """Append-only and line-delimited, so a crash mid-engagement does not lose
    the record of what was attempted."""
    scope = make(tmp_path)
    scope.authorize("127.0.0.9", 8080, "connect")
    audit = tmp_path / "audit.jsonl"
    assert audit.exists(), "the refusal must be on disk before the process ends"
    lines = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 1
    assert lines[0]["allowed"] is False
    assert "not within any target" in lines[0]["reason"]


def test_every_record_carries_a_time_and_the_engagement(tmp_path):
    scope = make(tmp_path)
    scope.authorize("127.0.0.1", 8080, "connect")
    entry = scope.audit.entries[0]
    assert entry["at"] and entry["engagement"] == "unit test"
    assert entry["host"] == "127.0.0.1" and entry["port"] == 8080


def test_the_audit_log_appends_rather_than_replacing(tmp_path):
    scope = make(tmp_path)
    scope.authorize("127.0.0.1", 8080, "connect")
    again = load_scope(tmp_path / "engagement.json", audit_path=tmp_path / "audit.jsonl")
    again.authorize("127.0.0.1", 8080, "connect")
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2


# --- an engagement file that half-parses is worse than one that does not ---

@pytest.mark.parametrize("data,message", [
    ({"targets": [], "allowed_actions": ["connect"]}, "must name the engagement"),
    ({"engagement": "x", "allowed_actions": ["connect"]}, "must name its targets"),
    ({"engagement": "x", "targets": []}, "must list the actions"),
    ({"engagement": "x", "targets": [{}], "allowed_actions": ["connect"]}, "must name a host or a cidr"),
    ({"engagement": "x", "targets": [{"host": "127.0.0.1"}], "allowed_actions": []},
     "must list the actions"),
])
def test_an_unusable_engagement_file_raises(tmp_path, data, message):
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ScopeError) as raised:
        load_scope(path)
    assert message in str(raised.value)


def test_a_missing_engagement_file_raises(tmp_path):
    with pytest.raises(ScopeError):
        load_scope(tmp_path / "absent.json")


def test_a_bad_timestamp_raises_rather_than_being_ignored(tmp_path):
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps({
        "engagement": "x", "targets": [{"host": "127.0.0.1"}], "allowed_actions": ["connect"],
        "window": {"start": "not a time"},
    }), encoding="utf-8")
    with pytest.raises(ScopeError):
        load_scope(path)


def test_yaml_engagements_load(tmp_path):
    path = tmp_path / "engagement.yaml"
    path.write_text(
        "engagement: yaml test\n"
        "targets:\n  - host: 127.0.0.1\n    ports: [443]\n"
        "allowed_actions:\n  - connect\n", encoding="utf-8")
    scope = load_scope(path)
    assert scope.engagement == "yaml test"
    assert scope.authorize("127.0.0.1", 443, "connect")


# --- reporting -------------------------------------------------------------

def test_hosts_expands_a_cidr_without_widening_the_decision(tmp_path):
    scope = make(tmp_path, targets=[{"cidr": "127.0.0.0/30", "ports": [80]}])
    assert scope.hosts() == ["127.0.0.1", "127.0.0.2"]
    # being in hosts() is not permission: the port still has to be listed
    assert not scope.authorize("127.0.0.1", 81, "connect")


def test_the_scope_describes_itself(tmp_path):
    scope = make(tmp_path)
    described = scope.as_dict()
    assert described["engagement"] == "unit test"
    assert described["allowed_actions"] == ["banner", "connect"]
    assert described["targets"] == [{"host": "127.0.0.1", "ports": [8080]}]
