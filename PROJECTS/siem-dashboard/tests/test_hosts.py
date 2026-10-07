"""Host registry: enrolment, key authentication, liveness, and safe removal.

The unit tests run against a bare connection holding only the ``hosts`` table.
The two removal tests that need the event store open it through
``app.get_connection`` so the refusal-to-orphan check runs against the real
``live_events`` schema.
"""
import sqlite3
from contextlib import contextmanager

import pytest

from src.app import get_connection
from src.hosts import (
    NEVER_REPORTED,
    ONLINE,
    STALE,
    disable_host,
    enable_host,
    enrol_host,
    ensure_schema,
    get_host,
    host_summary,
    list_hosts,
    remove_host,
    rotate_host_key,
    touch_host,
    verify_host_key,
)


@contextmanager
def _registry(tmp_path):
    connection = sqlite3.connect(tmp_path / "hosts.db")
    connection.row_factory = sqlite3.Row
    ensure_schema(connection)
    try:
        yield connection
    finally:
        connection.close()


@contextmanager
def _live_registry(tmp_path):
    connection = get_connection(tmp_path / "live.db")
    ensure_schema(connection)
    try:
        yield connection
    finally:
        connection.close()


def _aged(conn, host_id, seconds):
    """Push a host's last_seen into the past to exercise the stale window."""

    conn.execute(
        "UPDATE hosts SET last_seen = datetime('now', ?) WHERE host_id = ?",
        (f"-{seconds} seconds", host_id),
    )
    conn.commit()


def test_ensure_schema_is_idempotent_and_keeps_rows(tmp_path):
    with _registry(tmp_path) as conn:
        enrol_host(conn, "lab-pc")
        ensure_schema(conn)
        ensure_schema(conn)
        assert len(list_hosts(conn)) == 1


def test_enrol_returns_id_and_a_one_time_key(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc", platform="windows", agent_version="1.2.0")
        assert host["host_id"] == 1
        assert host["name"] == "lab-pc"
        assert host["platform"] == "windows"
        assert host["agent_version"] == "1.2.0"
        assert host["key"].startswith("hk_")
        # "hk_" plus 43 base64url characters (256 bits of randomness).
        assert len(host["key"]) == 46
        assert host["first_seen"] == host["last_seen"]
        assert host["event_count"] == 0
        assert host["enabled"] is True
        assert host["status"] == NEVER_REPORTED
        # A second may tick between the timestamp enrol writes and the timestamp
        # the record is built from, and the age is truncated to whole seconds, so
        # the freshly enrolled host reads as zero or one -- never more.
        assert host["age_seconds"] in (0, 1)


def test_platform_and_version_default_to_empty(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        assert host["platform"] == ""
        assert host["agent_version"] == ""


def test_name_is_stripped(tmp_path):
    with _registry(tmp_path) as conn:
        assert enrol_host(conn, "  lab-pc  ")["name"] == "lab-pc"


@pytest.mark.parametrize("bad", ["", "   ", None, 5])
def test_bad_name_is_rejected(tmp_path, bad):
    with _registry(tmp_path) as conn:
        with pytest.raises(ValueError, match="name must be a non-empty string"):
            enrol_host(conn, bad)


def test_duplicate_name_is_rejected(tmp_path):
    with _registry(tmp_path) as conn:
        enrol_host(conn, "lab-pc")
        with pytest.raises(ValueError, match="already enrolled"):
            enrol_host(conn, "lab-pc")


def test_only_a_salted_hash_is_stored(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        other = enrol_host(conn, "lab-pc-2")
        row = conn.execute(
            "SELECT key_salt, key_hash FROM hosts WHERE host_id = ?",
            (host["host_id"],),
        ).fetchone()
        other_row = conn.execute(
            "SELECT key_salt FROM hosts WHERE host_id = ?", (other["host_id"],)
        ).fetchone()
        # The plaintext key is nowhere in the row.
        assert row["key_hash"] != host["key"]
        assert host["key"] not in row["key_hash"]
        # A 32-byte SHA-256 digest and a 16-byte salt, hex-encoded.
        assert len(bytes.fromhex(row["key_hash"])) == 32
        assert len(bytes.fromhex(row["key_salt"])) == 16
        # The salt is per host, so the same key would still hash differently.
        assert other_row["key_salt"] != row["key_salt"]


def test_verify_accepts_the_key_and_rejects_others(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        assert verify_host_key(conn, host["host_id"], host["key"]) is True
        assert verify_host_key(conn, host["host_id"], "hk_wrong") is False
        assert verify_host_key(conn, host["host_id"], host["key"] + "x") is False


def test_verify_unknown_host_returns_false(tmp_path):
    with _registry(tmp_path) as conn:
        assert verify_host_key(conn, 999, "hk_whatever") is False


def test_verify_rejects_bad_input(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        for bad_id in (0, -1, "1", True):
            with pytest.raises(ValueError, match="host_id"):
                verify_host_key(conn, bad_id, host["key"])
        for bad_key in ("", None, 5):
            with pytest.raises(ValueError, match="key must be a non-empty string"):
                verify_host_key(conn, host["host_id"], bad_key)


def test_verify_uses_a_constant_time_comparison(tmp_path, monkeypatch):
    import src.hosts as hosts_module

    calls = []
    real = hosts_module.hmac.compare_digest

    def spy(left, right):
        calls.append((left, right))
        return real(left, right)

    monkeypatch.setattr(hosts_module.hmac, "compare_digest", spy)
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        assert verify_host_key(conn, host["host_id"], host["key"]) is True
        assert calls, "verification must go through compare_digest"
        assert calls[0][0] == calls[0][1]


def test_touch_updates_last_seen_and_increments(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        _aged(conn, host["host_id"], 10)
        touched = touch_host(conn, host["host_id"], 5)
        assert touched["event_count"] == 5
        assert touched["status"] == ONLINE
        # The host was aged ten seconds and the touch refreshed it, so the age
        # drops to nearly nothing. It is not asserted as exactly zero because the
        # touch stamps last_seen and the record is then built from a second
        # reading of the clock: a tick in between makes the truncated age one.
        assert touched["age_seconds"] in (0, 1)
        assert touch_host(conn, host["host_id"], 3)["event_count"] == 8


def test_touch_without_events_still_marks_seen(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        touch_host(conn, host["host_id"], 2)
        _aged(conn, host["host_id"], 400)
        assert get_host(conn, host["host_id"])["status"] == STALE
        touch_host(conn, host["host_id"])
        updated = get_host(conn, host["host_id"])
        assert updated["event_count"] == 2
        assert updated["status"] == ONLINE


def test_touch_rejects_bad_input(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        with pytest.raises(ValueError, match="event_count"):
            touch_host(conn, host["host_id"], -1)
        with pytest.raises(ValueError, match="event_count"):
            touch_host(conn, host["host_id"], 1.5)
        with pytest.raises(ValueError, match="No host with id 999"):
            touch_host(conn, 999)


def test_list_hosts_computes_status_and_age(tmp_path):
    with _registry(tmp_path) as conn:
        fresh = enrol_host(conn, "fresh")
        touch_host(conn, fresh["host_id"], 4)
        old = enrol_host(conn, "old")
        touch_host(conn, old["host_id"], 9)
        _aged(conn, old["host_id"], 1000)
        enrol_host(conn, "idle")      # never reports, so it must come back as such

        hosts = {host["name"]: host for host in list_hosts(conn, stale_after_seconds=300)}
        assert hosts["fresh"]["status"] == ONLINE
        assert hosts["fresh"]["event_count"] == 4
        assert hosts["old"]["status"] == STALE
        assert hosts["old"]["age_seconds"] >= 999
        assert hosts["idle"]["status"] == NEVER_REPORTED
        assert hosts["idle"]["event_count"] == 0


def test_stale_boundary_follows_the_window(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        touch_host(conn, host["host_id"], 1)
        _aged(conn, host["host_id"], 250)
        assert get_host(conn, host["host_id"])["status"] == ONLINE
        _aged(conn, host["host_id"], 350)
        assert get_host(conn, host["host_id"])["status"] == STALE


def test_list_hosts_is_sorted_by_name(tmp_path):
    with _registry(tmp_path) as conn:
        for name in ("zeta", "alpha", "Mid"):
            enrol_host(conn, name)
        assert [host["name"] for host in list_hosts(conn)] == ["alpha", "Mid", "zeta"]


@pytest.mark.parametrize("bad", [-1, 1.5, True, "300"])
def test_list_hosts_rejects_bad_window(tmp_path, bad):
    with _registry(tmp_path) as conn:
        with pytest.raises(ValueError, match="stale_after_seconds"):
            list_hosts(conn, bad)


def test_host_summary_counts_each_status(tmp_path):
    with _registry(tmp_path) as conn:
        online = enrol_host(conn, "a")
        touch_host(conn, online["host_id"], 1)
        stale = enrol_host(conn, "b")
        touch_host(conn, stale["host_id"], 1)
        _aged(conn, stale["host_id"], 900)
        enrol_host(conn, "c")
        assert host_summary(conn, 300) == {
            "online": 1,
            "stale": 1,
            "never-reported": 1,
            "total": 3,
        }


def test_host_summary_of_empty_registry(tmp_path):
    with _registry(tmp_path) as conn:
        assert host_summary(conn) == {
            "online": 0,
            "stale": 0,
            "never-reported": 0,
            "total": 0,
        }


def test_get_host_returns_record_and_rejects_unknown(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        fetched = get_host(conn, host["host_id"])
        assert fetched["name"] == "lab-pc"
        assert "key" not in fetched
        with pytest.raises(ValueError, match="No host with id 999"):
            get_host(conn, 999)


def test_disable_and_enable_toggle_the_flag(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        assert disable_host(conn, host["host_id"])["enabled"] is False
        assert get_host(conn, host["host_id"])["enabled"] is False
        # Idempotent.
        assert disable_host(conn, host["host_id"])["enabled"] is False
        assert enable_host(conn, host["host_id"])["enabled"] is True
        with pytest.raises(ValueError, match="No host"):
            disable_host(conn, 999)
        with pytest.raises(ValueError, match="No host"):
            enable_host(conn, 999)


def test_rotate_issues_a_new_key_and_invalidates_the_old(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        old_key = host["key"]
        rotated = rotate_host_key(conn, host["host_id"])
        assert rotated["key"].startswith("hk_")
        assert rotated["key"] != old_key
        assert rotated["key_created_at"] >= host["key_created_at"]
        assert verify_host_key(conn, host["host_id"], old_key) is False
        assert verify_host_key(conn, host["host_id"], rotated["key"]) is True
        with pytest.raises(ValueError, match="No host"):
            rotate_host_key(conn, 999)


def test_remove_refuses_when_the_host_has_reported(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        touch_host(conn, host["host_id"], 3)
        with pytest.raises(ValueError, match="has reported 3 event"):
            remove_host(conn, host["host_id"])
        assert get_host(conn, host["host_id"])["name"] == "lab-pc"


def test_remove_deletes_a_host_with_no_events(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        assert remove_host(conn, host["host_id"]) is None
        with pytest.raises(ValueError, match="No host"):
            get_host(conn, host["host_id"])
        assert list_hosts(conn) == []


def test_remove_rejects_unknown_host(tmp_path):
    with _registry(tmp_path) as conn:
        with pytest.raises(ValueError, match="No host with id 999"):
            remove_host(conn, 999)


def test_remove_refuses_when_live_events_reference_the_host(tmp_path):
    with _live_registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        conn.execute(
            "INSERT INTO live_events(timestamp,channel,provider,event_id,level,"
            "severity,username,host,source_ip,message,record_id,source) VALUES "
            "('2026-10-01 12:00:00','System','p','1','Information','Low','u',"
            "'lab-pc','local','m','r','api')"
        )
        conn.commit()
        # event_count is still 0, but the store holds an event for this host.
        with pytest.raises(ValueError, match="still has 1 event"):
            remove_host(conn, host["host_id"])
        remove_host(conn, host["host_id"], force=True)
        with pytest.raises(ValueError, match="No host"):
            get_host(conn, host["host_id"])
        # Force removed the registry entry, not the event.
        assert conn.execute("SELECT COUNT(*) FROM live_events").fetchone()[0] == 1


def test_force_removes_a_reporting_host(tmp_path):
    with _registry(tmp_path) as conn:
        host = enrol_host(conn, "lab-pc")
        touch_host(conn, host["host_id"], 2)
        remove_host(conn, host["host_id"], force=True)
        assert list_hosts(conn) == []
