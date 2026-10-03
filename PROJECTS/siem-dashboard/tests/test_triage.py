"""The triage workflow: state, assignment, notes, suppression and the queue.

Every test drives the public functions against a real SQLite store created by
``app.get_connection``, so the module is exercised against the same schema the
running console uses.
"""

from datetime import datetime, timezone

import pytest

from src.app import get_connection
from src.triage import (
    add_note,
    assign,
    ensure_schema,
    is_suppressed,
    list_detections,
    list_notes,
    list_suppressions,
    list_transitions,
    set_status,
    suggest_suppression,
    suppress,
    suppression_for,
    triage_summary,
    unsuppress,
)


def make_conn(tmp_path):
    conn = get_connection(tmp_path / "live.db")
    ensure_schema(conn)
    return conn


def add_alert(
    conn,
    host="LAB-A",
    rule_id="rule-x",
    event_id="4625",
    severity="High",
    is_alert=1,
    timestamp=None,
):
    """Insert one stored event and return its row id."""

    stamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    cursor = conn.execute(
        "INSERT INTO live_events(timestamp,channel,provider,event_id,level,severity,username,host,"
        "source_ip,message,record_id,source,is_alert,rule_name,raw_log,external_id,rule_id,"
        "techniques,matched_on,enrichment) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            stamp, "Security", "provider", event_id, "Information", severity, "admin", host,
            "local", "message", "", "test", is_alert, "Rule", "", "", rule_id, "", "", "",
        ),
    )
    conn.commit()
    return cursor.lastrowid


def detection(conn, host="LAB-A", rule_id="rule-x", event_id="4625", **kwargs):
    """Insert an alert and return the detection dict the API takes."""

    row_id = add_alert(conn, host=host, rule_id=rule_id, event_id=event_id, **kwargs)
    return {"id": row_id, "host": host, "rule_id": rule_id, "event_id": event_id}


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #

def test_ensure_schema_is_idempotent(tmp_path):
    conn = make_conn(tmp_path)
    ensure_schema(conn)  # a second call must not raise
    names = {
        str(row["name"])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert {
        "detection_state",
        "detection_transitions",
        "detection_notes",
        "suppressions",
    } <= names


# --------------------------------------------------------------------------- #
# Status and history
# --------------------------------------------------------------------------- #

def test_set_status_records_state_and_history(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn)
    state = set_status(conn, det, "acknowledged", "alice")

    assert state["status"] == "acknowledged"
    assert state["updated_by"] == "alice"
    assert state["event_id"] == str(det["id"])
    assert state["assignee"] == ""

    history = list_transitions(conn, det)
    assert [entry["to_status"] for entry in history] == ["acknowledged"]
    assert history[0]["from_status"] == "new"
    assert history[0]["actor"] == "alice"


def test_set_status_records_every_call_even_a_repeat(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn)
    set_status(conn, det, "acknowledged", "alice")
    set_status(conn, det, "acknowledged", "bob")

    history = list_transitions(conn, det)
    assert len(history) == 2
    assert history[-1]["from_status"] == "acknowledged"
    assert history[-1]["to_status"] == "acknowledged"
    assert history[-1]["actor"] == "bob"


def test_set_status_changes_assignee_only_when_given(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn)

    assert set_status(conn, det, "investigating", "alice", assignee="bob")["assignee"] == "bob"
    assert set_status(conn, det, "closed", "alice")["assignee"] == "bob"
    assert set_status(conn, det, "investigating", "alice", assignee="carol")["assignee"] == "carol"


# --------------------------------------------------------------------------- #
# Assignment
# --------------------------------------------------------------------------- #

def test_assign_keeps_status_and_adds_no_transition(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn)
    set_status(conn, det, "investigating", "alice")
    before = len(list_transitions(conn, det))

    state = assign(conn, det, "bob", "alice")

    assert state["status"] == "investigating"
    assert state["assignee"] == "bob"
    assert state["updated_by"] == "alice"
    assert len(list_transitions(conn, det)) == before


def test_assign_without_prior_state_starts_as_new(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn)

    state = assign(conn, det, "bob", "alice")

    assert state["status"] == "new"
    assert state["assignee"] == "bob"
    assert list_transitions(conn, det) == []


# --------------------------------------------------------------------------- #
# Notes
# --------------------------------------------------------------------------- #

def test_add_note_is_append_only_and_ordered(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn)

    add_note(conn, det, "alice", "first")
    add_note(conn, det, "bob", "second")

    notes = list_notes(conn, det)
    assert [note["text"] for note in notes] == ["first", "second"]
    assert [note["author"] for note in notes] == ["alice", "bob"]
    assert len(notes) == 2


def test_notes_are_per_detection(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn, rule_id="rule-x")
    other = detection(conn, rule_id="rule-y")

    add_note(conn, det, "alice", "for rule-x")

    assert [note["text"] for note in list_notes(conn, det)] == ["for rule-x"]
    assert list_notes(conn, other) == []


def test_notes_survive_later_status_and_assignment(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn)

    add_note(conn, det, "alice", "the investigation record")
    set_status(conn, det, "closed", "bob")
    assign(conn, det, "carol", "bob")

    assert list_notes(conn, det)[0]["text"] == "the investigation record"


# --------------------------------------------------------------------------- #
# Suppression: scope, matching and expiry
# --------------------------------------------------------------------------- #

def test_host_scoped_suppression_silences_one_host(tmp_path):
    conn = make_conn(tmp_path)
    host_a = detection(conn, host="LAB-A", rule_id="rule-x")
    host_b = detection(conn, host="LAB-B", rule_id="rule-x")

    rule = suppress(conn, "rule-x", host_id="LAB-A", scope="host", actor="alice")

    assert rule["scope"] == "host"
    assert rule["active"] is True
    assert is_suppressed(conn, "LAB-A", "rule-x") is True
    assert is_suppressed(conn, "LAB-B", "rule-x") is False

    queue_ids = [item["id"] for item in list_detections(conn)["detections"]]
    assert host_a["id"] not in queue_ids
    assert host_b["id"] in queue_ids


def test_global_suppression_silences_every_host(tmp_path):
    conn = make_conn(tmp_path)
    detection(conn, host="LAB-A", rule_id="rule-x")
    detection(conn, host="LAB-B", rule_id="rule-x")

    rule = suppress(conn, "rule-x", scope="global", actor="alice")

    assert rule["host_id"] == ""
    assert is_suppressed(conn, "LAB-A", "rule-x") is True
    assert is_suppressed(conn, "LAB-B", "rule-x") is True
    assert list_detections(conn)["total"] == 0


def test_suppression_only_applies_to_its_rule(tmp_path):
    conn = make_conn(tmp_path)
    suppress(conn, "rule-x", host_id="LAB-A", actor="alice")
    assert is_suppressed(conn, "LAB-A", "rule-y") is False


def test_host_scoped_suppression_does_not_apply_to_unknown_host(tmp_path):
    conn = make_conn(tmp_path)
    suppress(conn, "rule-x", host_id="LAB-A", scope="host", actor="alice")
    assert is_suppressed(conn, None, "rule-x") is False


def test_expired_suppression_stops_applying_on_its_own(tmp_path):
    conn = make_conn(tmp_path)
    rule = suppress(conn, "rule-x", host_id="LAB-A", actor="alice", expires_days=1)
    assert rule["expires_at"] != ""
    assert is_suppressed(conn, "LAB-A", "rule-x") is True

    # Age the rule out; nothing else is done to it.
    conn.execute(
        "UPDATE suppressions SET expires_at = ? WHERE id = ?",
        ("2000-01-01T00:00:00+00:00", rule["id"]),
    )
    conn.commit()

    assert is_suppressed(conn, "LAB-A", "rule-x") is False
    assert suppression_for(conn, "LAB-A", "rule-x") is None
    assert {item["id"]: item["active"] for item in list_suppressions(conn)}[rule["id"]] is False


def test_suppression_without_expiry_never_expires(tmp_path):
    conn = make_conn(tmp_path)
    rule = suppress(conn, "rule-x", host_id="LAB-A", actor="alice")
    assert rule["expires_at"] == ""
    assert is_suppressed(conn, "LAB-A", "rule-x") is True


def test_suppression_for_prefers_host_scope_over_global(tmp_path):
    conn = make_conn(tmp_path)
    global_rule = suppress(conn, "rule-x", scope="global", reason="global", actor="alice")
    host_rule = suppress(conn, "rule-x", host_id="LAB-A", reason="host", actor="alice")

    found = suppression_for(conn, "LAB-A", "rule-x")
    assert found["id"] == host_rule["id"]
    assert found["scope"] == "host"

    # A host with no host-scoped rule falls back to the global one.
    assert suppression_for(conn, "LAB-Z", "rule-x")["id"] == global_rule["id"]


def test_suppression_for_is_none_when_nothing_matches(tmp_path):
    conn = make_conn(tmp_path)
    assert suppression_for(conn, "LAB-A", "rule-x") is None
    assert is_suppressed(conn, "LAB-A", "rule-x") is False


# --------------------------------------------------------------------------- #
# Suppression: revoking and listing
# --------------------------------------------------------------------------- #

def test_unsuppress_revokes_and_records_actor(tmp_path):
    conn = make_conn(tmp_path)
    rule = suppress(conn, "rule-x", host_id="LAB-A", actor="alice")
    assert is_suppressed(conn, "LAB-A", "rule-x") is True

    revoked = unsuppress(conn, rule["id"], "carol")

    assert revoked["active"] is False
    assert revoked["revoked_by"] == "carol"
    assert revoked["revoked_at"] != ""
    assert is_suppressed(conn, "LAB-A", "rule-x") is False
    # The row is kept, so the tuning history survives.
    assert any(item["id"] == rule["id"] for item in list_suppressions(conn))


def test_unsuppress_twice_is_a_noop(tmp_path):
    conn = make_conn(tmp_path)
    rule = suppress(conn, "rule-x", host_id="LAB-A", actor="alice")
    first = unsuppress(conn, rule["id"], "carol")
    second = unsuppress(conn, rule["id"], "dave")

    assert second["revoked_by"] == "carol"  # not overwritten by the second call
    assert second["revoked_at"] == first["revoked_at"]


def test_list_suppressions_is_newest_first(tmp_path):
    conn = make_conn(tmp_path)
    first = suppress(conn, "rule-x", host_id="LAB-A", actor="alice")
    second = suppress(conn, "rule-y", host_id="LAB-B", actor="alice")

    assert [item["id"] for item in list_suppressions(conn)] == [second["id"], first["id"]]


def test_suppression_is_a_convenience_the_event_is_still_stored(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn, host="LAB-A", rule_id="rule-x")

    suppress(conn, "rule-x", host_id="LAB-A", actor="alice")

    # Hidden from the queue...
    assert list_detections(conn)["total"] == 0
    # ...but the detection still fired and is still in the store.
    stored = conn.execute(
        "SELECT is_alert, rule_id FROM live_events WHERE id = ?", (det["id"],)
    ).fetchone()
    assert stored["is_alert"] == 1
    assert stored["rule_id"] == "rule-x"


# --------------------------------------------------------------------------- #
# The false-positive offer
# --------------------------------------------------------------------------- #

def test_suggest_suppression_offers_without_writing(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn, host="LAB-A", rule_id="rule-x")

    offer = suggest_suppression(conn, det)

    assert offer == {
        "rule_id": "rule-x",
        "host_id": "LAB-A",
        "scope": "host",
        "reason": "False positive: rule-x on LAB-A",
        "already_suppressed": False,
    }
    assert list_suppressions(conn) == []


def test_false_positive_offers_suppression_but_does_not_create_it(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn)

    state = set_status(conn, det, "false_positive", "alice")

    assert state["status"] == "false_positive"
    assert state["suppression_offer"]["rule_id"] == "rule-x"
    assert state["suppression_offer"]["already_suppressed"] is False
    # Offered, never silently performed.
    assert list_suppressions(conn) == []
    assert is_suppressed(conn, "LAB-A", "rule-x") is False


def test_other_statuses_carry_no_suppression_offer(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn)
    assert "suppression_offer" not in set_status(conn, det, "closed", "alice")


def test_suggest_suppression_is_none_without_a_rule(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn, rule_id="")
    assert suggest_suppression(conn, det) is None


def test_offer_reports_an_existing_suppression(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn)
    suppress(conn, "rule-x", host_id="LAB-A", actor="alice")
    assert suggest_suppression(conn, det)["already_suppressed"] is True


# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

def test_triage_summary_counts_each_status(tmp_path):
    conn = make_conn(tmp_path)
    first = detection(conn, host="LAB-A", rule_id="rule-x")
    second = detection(conn, host="LAB-B", rule_id="rule-x")
    third = detection(conn, host="LAB-C", rule_id="rule-y")

    set_status(conn, first, "acknowledged", "alice")
    set_status(conn, second, "investigating", "alice")
    set_status(conn, third, "closed", "alice")

    summary = triage_summary(conn)
    assert summary["new"] == 0
    assert summary["acknowledged"] == 1
    assert summary["investigating"] == 1
    assert summary["closed"] == 1
    assert summary["false_positive"] == 0
    assert summary["Total"] == 3
    assert summary["Suppressed"] == 0


def test_triage_summary_counts_untouched_detections_as_new(tmp_path):
    conn = make_conn(tmp_path)
    detection(conn, host="LAB-A", rule_id="rule-x")
    detection(conn, host="LAB-B", rule_id="rule-x")

    summary = triage_summary(conn)
    assert summary["new"] == 2
    assert summary["Total"] == 2


def test_triage_summary_on_an_empty_store(tmp_path):
    conn = make_conn(tmp_path)
    summary = triage_summary(conn)
    for key in ("new", "acknowledged", "investigating", "closed", "false_positive"):
        assert summary[key] == 0
    assert summary["Total"] == 0
    assert summary["Suppressed"] == 0


def test_triage_summary_reports_suppressed_separately(tmp_path):
    conn = make_conn(tmp_path)
    detection(conn, host="LAB-A", rule_id="rule-x")
    detection(conn, host="LAB-B", rule_id="rule-x")

    suppress(conn, "rule-x", host_id="LAB-A", actor="alice")

    summary = triage_summary(conn)
    assert summary["Total"] == 1
    assert summary["new"] == 1
    assert summary["Suppressed"] == 1


# --------------------------------------------------------------------------- #
# The queue
# --------------------------------------------------------------------------- #

def test_list_detections_returns_queue_with_total(tmp_path):
    conn = make_conn(tmp_path)
    detection(conn, host="LAB-A", rule_id="rule-x", severity="Low")
    detection(conn, host="LAB-B", rule_id="rule-y", severity="High")

    queue = list_detections(conn)

    assert queue["total"] == 2
    assert queue["count"] == 2
    assert queue["limit"] == 50
    assert queue["offset"] == 0
    # Severity first: High before Low.
    assert [item["severity"] for item in queue["detections"]] == ["High", "Low"]
    assert {"status", "assignee", "updated_at", "updated_by"} <= set(queue["detections"][0])


def test_list_detections_pages_with_limit_and_offset(tmp_path):
    conn = make_conn(tmp_path)
    for index in range(5):
        detection(conn, host=f"LAB-{index}", rule_id="rule-x")

    page_one = list_detections(conn, limit=2, offset=0)
    page_two = list_detections(conn, limit=2, offset=2)

    assert page_one["total"] == 5
    assert page_one["count"] == 2
    assert page_two["count"] == 2
    assert {item["id"] for item in page_one["detections"]}.isdisjoint(
        {item["id"] for item in page_two["detections"]}
    )


def test_list_detections_filters_by_status_host_and_assignee(tmp_path):
    conn = make_conn(tmp_path)
    owned = detection(conn, host="LAB-A", rule_id="rule-x")
    other = detection(conn, host="LAB-B", rule_id="rule-x")
    set_status(conn, owned, "acknowledged", "alice", assignee="bob")

    assert [item["id"] for item in list_detections(conn, status="acknowledged")["detections"]] == [owned["id"]]
    assert [item["id"] for item in list_detections(conn, host_id="LAB-B")["detections"]] == [other["id"]]
    assert [item["id"] for item in list_detections(conn, assignee="bob")["detections"]] == [owned["id"]]
    assert list_detections(conn, assignee="nobody")["total"] == 0


def test_list_detections_ignores_events_that_are_not_alerts(tmp_path):
    conn = make_conn(tmp_path)
    add_alert(conn, host="LAB-A", rule_id="rule-x", is_alert=0)
    assert list_detections(conn)["total"] == 0
    assert triage_summary(conn)["Total"] == 0


def test_list_detections_clamps_paging_values(tmp_path):
    conn = make_conn(tmp_path)
    detection(conn)
    assert list_detections(conn, limit=0)["limit"] == 1
    assert list_detections(conn, limit=100000)["limit"] == 500
    assert list_detections(conn, offset=-10)["offset"] == 0


# --------------------------------------------------------------------------- #
# Error paths
# --------------------------------------------------------------------------- #

def test_set_status_rejects_an_unknown_status(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn)
    with pytest.raises(ValueError, match="Unsupported status"):
        set_status(conn, det, "escalated", "alice")


def test_set_status_requires_an_actor(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn)
    with pytest.raises(ValueError, match="actor is required"):
        set_status(conn, det, "closed", "   ")


def test_detection_identity_is_required(tmp_path):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError, match="mapping"):
        set_status(conn, "not-a-detection", "closed", "alice")
    with pytest.raises(ValueError, match="host"):
        set_status(conn, {"rule_id": "rule-x", "id": 1}, "closed", "alice")
    with pytest.raises(ValueError, match="rule_id"):
        set_status(conn, {"host": "LAB-A", "id": 1}, "closed", "alice")
    with pytest.raises(ValueError, match="event id"):
        set_status(conn, {"host": "LAB-A", "rule_id": "rule-x"}, "closed", "alice")


def test_assign_requires_an_assignee(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn)
    with pytest.raises(ValueError, match="assignee is required"):
        assign(conn, det, "  ", "alice")


def test_add_note_requires_author_and_text(tmp_path):
    conn = make_conn(tmp_path)
    det = detection(conn)
    with pytest.raises(ValueError, match="author is required"):
        add_note(conn, det, "", "text")
    with pytest.raises(ValueError, match="text is required"):
        add_note(conn, det, "alice", "   ")


def test_suppress_rejects_an_unknown_scope(tmp_path):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError, match="Unsupported scope"):
        suppress(conn, "rule-x", scope="cluster", actor="alice")


def test_suppress_host_scope_requires_a_host(tmp_path):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError, match="host_id"):
        suppress(conn, "rule-x", scope="host", actor="alice")


def test_suppress_global_scope_rejects_a_host(tmp_path):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError, match="only valid with scope='host'"):
        suppress(conn, "rule-x", host_id="LAB-A", scope="global", actor="alice")


def test_suppress_rejects_a_bad_expiry(tmp_path):
    conn = make_conn(tmp_path)
    for bad in (0, -1, "3", 1.5, True):
        with pytest.raises(ValueError, match="expires_days"):
            suppress(conn, "rule-x", host_id="LAB-A", actor="alice", expires_days=bad)


def test_suppress_requires_a_rule_and_an_actor(tmp_path):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError, match="rule_id is required"):
        suppress(conn, "", host_id="LAB-A", actor="alice")
    with pytest.raises(ValueError, match="actor is required"):
        suppress(conn, "rule-x", host_id="LAB-A", actor="")


def test_suppression_for_requires_a_rule(tmp_path):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError, match="rule_id is required"):
        suppression_for(conn, "LAB-A", "")


def test_unsuppress_rejects_an_unknown_id(tmp_path):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError, match="No suppression"):
        unsuppress(conn, 999, "alice")
    with pytest.raises(ValueError, match="whole number"):
        unsuppress(conn, "not-a-number", "alice")


def test_list_detections_rejects_an_unknown_status(tmp_path):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError, match="Unsupported status"):
        list_detections(conn, status="escalated")


def test_bad_paging_values_raise(tmp_path):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError, match="whole number"):
        list_detections(conn, limit="many")
    with pytest.raises(ValueError, match="whole number"):
        list_detections(conn, offset=True)


# --------------------------------------------------------------------------- #
# Input normalisation
# --------------------------------------------------------------------------- #

def test_suppress_trims_its_arguments(tmp_path):
    conn = make_conn(tmp_path)
    rule = suppress(conn, "  rule-x  ", host_id="  LAB-A  ", scope=" HOST ", actor=" alice ")
    assert rule["rule_id"] == "rule-x"
    assert rule["host_id"] == "LAB-A"
    assert rule["scope"] == "host"
    assert rule["actor"] == "alice"
    assert is_suppressed(conn, "LAB-A", "rule-x") is True
