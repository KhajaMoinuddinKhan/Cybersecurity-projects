"""Login lockout and TOTP multi-factor authentication must behave as documented."""
import base64
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from src import auth
from src.security import (
    DEFAULT_LOCKOUT_SECONDS,
    DEFAULT_MAX_FAILURES,
    DEFAULT_WINDOW_SECONDS,
    RECOVERY_CODE_COUNT,
    TOTP_DIGITS,
    TOTP_PERIOD,
    _decode_secret,
    _hotp,
    clear_lockout,
    confirm_enrolment,
    disable_mfa,
    ensure_schema,
    generate_secret,
    is_locked_out,
    lockout_summary,
    mfa_status,
    provisioning_uri,
    record_failure,
    record_success,
    start_enrolment,
    verify_code,
    verify_login_code,
)


def make_db(tmp_path):
    conn = sqlite3.connect(tmp_path / "security.db")
    auth.ensure_schema(conn)
    ensure_schema(conn)
    return conn


def audit_actions(conn):
    return [row["action"] for row in auth.list_audit(conn, limit=1000)]


def code_for(secret, at_time, digits=TOTP_DIGITS):
    """The code a correct implementation should produce for a moment in time."""
    counter = int(at_time // TOTP_PERIOD)
    return _hotp(_decode_secret(secret), counter, digits)


def now_code(secret):
    """A valid code for the current moment, for functions that use real time."""
    return code_for(secret, datetime.now(timezone.utc).timestamp())


# --- RFC 6238 test vectors -------------------------------------------------
#
# Source: RFC 6238, Appendix B, "Test Vectors", SHA-1 column, with the secret
# given in the same appendix as the ASCII string "12345678901234567890".
# The published codes are EIGHT digits; this module's verify_code is fixed at
# six digits (see the task spec), so the vectors are checked against the shared
# HOTP core (_hotp) with digits=8, which is the identical HMAC-SHA1 truncation
# path verify_code uses, only with a different final modulus. Because reducing
# a number modulo 10**6 is taking its last six digits, the last six digits of
# each published eight-digit code are also valid six-digit codes for the same
# secret and timestamp, and are checked through verify_code itself below.

RFC_SECRET_ASCII = b"12345678901234567890"  # RFC 6238 Appendix B
RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32 of the above
RFC_SHA1_VECTORS = (
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
)


def test_rfc6238_secret_encodes_to_the_documented_base32():
    assert base64.b32encode(RFC_SECRET_ASCII).decode("ascii") == RFC_SECRET_B32
    assert _decode_secret(RFC_SECRET_B32) == RFC_SECRET_ASCII


def test_rfc6238_sha1_eight_digit_vectors():
    for at_time, expected in RFC_SHA1_VECTORS:
        produced = _hotp(_decode_secret(RFC_SECRET_B32), at_time // TOTP_PERIOD, 8)
        assert produced == expected, f"at {at_time}: {produced} != {expected}"


def test_verify_code_accepts_rfc6238_six_digit_last_six():
    for at_time, expected in RFC_SHA1_VECTORS:
        last_six = expected[-6:]
        assert verify_code(RFC_SECRET_B32, last_six, at_time=at_time) is True, at_time


def test_verify_code_rejects_rfc_vector_codes_two_steps_away():
    # A vector's code is good for its own step and, because of the drift window,
    # the step either side; two steps away it must be refused.
    at_time, expected = RFC_SHA1_VECTORS[3]  # 1234567890 -> 89005924
    last_six = expected[-6:]
    assert verify_code(RFC_SECRET_B32, last_six, at_time=at_time) is True
    assert verify_code(RFC_SECRET_B32, last_six, at_time=at_time + 2 * TOTP_PERIOD) is False
    assert verify_code(RFC_SECRET_B32, last_six, at_time=at_time - 2 * TOTP_PERIOD) is False


# --- Secrets and URIs ------------------------------------------------------


def test_generate_secret_is_base32_160_bits():
    secret = generate_secret()
    assert len(secret) == 32
    assert secret == secret.upper()
    assert _decode_secret(secret) and len(_decode_secret(secret)) == 20
    assert generate_secret() != generate_secret()


def test_generate_secret_is_accepted_by_verify_code():
    secret = generate_secret()
    assert verify_code(secret, code_for(secret, 1_700_000_000), at_time=1_700_000_000)


def test_provisioning_uri_has_the_expected_fields():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    uri = provisioning_uri(secret, "alice")
    parsed = urlparse(uri)
    assert parsed.scheme == "otpauth"
    assert parsed.netloc == "totp"
    assert unquote(parsed.path).lstrip("/") == "SIEM console:alice"
    query = parse_qs(parsed.query)
    assert query["secret"] == [secret]
    assert query["issuer"] == ["SIEM console"]
    assert query["algorithm"] == ["SHA1"]
    assert query["digits"] == ["6"]
    assert query["period"] == ["30"]


def test_provisioning_uri_encodes_a_custom_issuer():
    secret = generate_secret()
    uri = provisioning_uri(secret, "bob", issuer="Acme Corp")
    parsed = urlparse(uri)
    assert unquote(parsed.path).lstrip("/") == "Acme Corp:bob"
    assert parse_qs(parsed.query)["issuer"] == ["Acme Corp"]


def test_provisioning_uri_rejects_a_bad_secret_and_username():
    with pytest.raises(ValueError, match="base32"):
        provisioning_uri("not base32 !!!", "alice")
    with pytest.raises(ValueError, match="username"):
        provisioning_uri(generate_secret(), "")


# --- verify_code: window, shape, errors ------------------------------------


def test_verify_code_accepts_current_step():
    secret = generate_secret()
    at = 1_700_000_000
    assert verify_code(secret, code_for(secret, at), at_time=at) is True


def test_verify_code_drift_window_is_plus_or_minus_one_by_default():
    secret = generate_secret()
    at = 1_700_000_000
    current = code_for(secret, at)
    previous = code_for(secret, at - TOTP_PERIOD)
    following = code_for(secret, at + TOTP_PERIOD)
    assert verify_code(secret, previous, at_time=at) is True
    assert verify_code(secret, following, at_time=at) is True
    assert verify_code(secret, current, at_time=at) is True


def test_verify_code_rejects_two_steps_away_by_default():
    secret = generate_secret()
    at = 1_700_000_000
    assert verify_code(secret, code_for(secret, at - 2 * TOTP_PERIOD), at_time=at) is False
    assert verify_code(secret, code_for(secret, at + 2 * TOTP_PERIOD), at_time=at) is False


def test_verify_code_window_zero_accepts_only_the_current_step():
    secret = generate_secret()
    at = 1_700_000_000
    assert verify_code(secret, code_for(secret, at), at_time=at, window=0) is True
    assert verify_code(secret, code_for(secret, at - TOTP_PERIOD), at_time=at, window=0) is False
    assert verify_code(secret, code_for(secret, at + TOTP_PERIOD), at_time=at, window=0) is False


def test_verify_code_window_two_reaches_two_steps():
    secret = generate_secret()
    at = 1_700_000_000
    assert verify_code(secret, code_for(secret, at - 2 * TOTP_PERIOD), at_time=at, window=2) is True


def test_verify_code_rejects_a_wrong_code():
    secret = generate_secret()
    at = 1_700_000_000
    good = code_for(secret, at)
    wrong = f"{(int(good) + 1) % 10 ** 6:06d}"
    assert verify_code(secret, wrong, at_time=at) is False


def test_verify_code_accepts_only_six_digit_codes():
    secret = generate_secret()
    at = 1_700_000_000
    good = code_for(secret, at)
    assert verify_code(secret, good, at_time=at) is True
    assert verify_code(secret, good[:5], at_time=at) is False       # five digits
    assert verify_code(secret, good + "0", at_time=at) is False     # seven digits
    assert verify_code(secret, "12a456", at_time=at) is False       # not digits
    assert verify_code(secret, 123456, at_time=at) is False         # not a string
    assert verify_code(secret, "", at_time=at) is False


def test_verify_code_accepts_a_datetime_reference_time():
    secret = generate_secret()
    at = 1_700_000_000
    moment = datetime.fromtimestamp(at, tz=timezone.utc)
    assert verify_code(secret, code_for(secret, at), at_time=moment) is True


def test_verify_code_raises_on_a_bad_secret_and_bad_window():
    with pytest.raises(ValueError, match="base32"):
        verify_code("not base32 !!!", "123456")
    with pytest.raises(ValueError, match="secret"):
        verify_code("", "123456")
    with pytest.raises(ValueError, match="window"):
        verify_code(generate_secret(), "123456", window=-1)
    with pytest.raises(ValueError, match="at_time"):
        verify_code(generate_secret(), "123456", at_time="soon")


# --- Recording attempts and locking out ------------------------------------


def test_record_failure_stores_an_attempt_and_counts_it(tmp_path):
    conn = make_db(tmp_path)
    result = record_failure(conn, "alice", "10.0.0.1")
    assert result["outcome"] == "failure"
    assert result["failure_count"] == 1
    assert result["locked"] is False
    row = conn.execute(
        "SELECT username, source_ip, outcome, timestamp FROM login_attempts"
    ).fetchone()
    assert (row["username"], row["source_ip"], row["outcome"]) == ("alice", "10.0.0.1", "failure")
    assert row["timestamp"]
    assert "login_failure" in audit_actions(conn)


def test_lockout_triggers_at_the_default_threshold(tmp_path):
    conn = make_db(tmp_path)
    for _ in range(DEFAULT_MAX_FAILURES - 1):
        assert record_failure(conn, "alice", "10.0.0.1")["locked"] is False
    final = record_failure(conn, "alice", "10.0.0.1")
    assert final["locked"] is True
    assert final["failure_count"] == DEFAULT_MAX_FAILURES
    state = is_locked_out(conn, "alice", "10.0.0.1")
    assert state["locked"] is True
    assert state["failure_count"] == DEFAULT_MAX_FAILURES
    assert state["locked_until"]
    assert 0 < state["remaining_seconds"] <= DEFAULT_LOCKOUT_SECONDS
    assert "lockout_triggered" in audit_actions(conn)


def test_max_failures_is_configurable(tmp_path):
    conn = make_db(tmp_path)
    assert record_failure(conn, "alice", "10.0.0.1", max_failures=3)["locked"] is False
    assert record_failure(conn, "alice", "10.0.0.1", max_failures=3)["locked"] is False
    assert record_failure(conn, "alice", "10.0.0.1", max_failures=3)["locked"] is True


def test_is_locked_out_before_any_failure(tmp_path):
    conn = make_db(tmp_path)
    state = is_locked_out(conn, "alice", "10.0.0.1")
    assert state["locked"] is False
    assert state["failure_count"] == 0
    assert state["locked_until"] is None
    assert state["remaining_seconds"] is None


def test_lockout_is_per_username_and_address(tmp_path):
    conn = make_db(tmp_path)
    for _ in range(DEFAULT_MAX_FAILURES):
        record_failure(conn, "alice", "10.0.0.1")
    assert is_locked_out(conn, "alice", "10.0.0.1")["locked"] is True
    assert is_locked_out(conn, "alice", "10.0.0.2")["locked"] is False
    assert is_locked_out(conn, "bob", "10.0.0.1")["locked"] is False


def test_lockout_expires_on_its_own(tmp_path):
    conn = make_db(tmp_path)
    for _ in range(DEFAULT_MAX_FAILURES):
        record_failure(conn, "alice", "10.0.0.1")
    assert is_locked_out(conn, "alice", "10.0.0.1")["locked"] is True

    # Move the stored expiry into the past to stand in for time passing.
    # is_locked_out is read-only and must report the lockout as over.
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(timespec="microseconds")
    conn.execute(
        "UPDATE lockouts SET locked_until = ? WHERE username = ? AND source_ip = ?",
        (past, "alice", "10.0.0.1"),
    )
    state = is_locked_out(conn, "alice", "10.0.0.1")
    assert state["locked"] is False
    assert state["locked_until"] is None
    assert state["remaining_seconds"] is None


def test_failures_outside_the_window_are_not_counted(tmp_path):
    conn = make_db(tmp_path)
    old = (datetime.now(timezone.utc) - timedelta(seconds=3600)).isoformat(timespec="microseconds")
    for _ in range(DEFAULT_MAX_FAILURES):
        conn.execute(
            "INSERT INTO login_attempts(username, source_ip, timestamp, outcome)"
            " VALUES (?,?,?, 'failure')",
            ("alice", "10.0.0.1", old),
        )
    state = is_locked_out(conn, "alice", "10.0.0.1")
    assert state["failure_count"] == 0
    assert state["locked"] is False


def test_window_seconds_controls_which_failures_count(tmp_path):
    conn = make_db(tmp_path)
    old = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat(timespec="microseconds")
    conn.execute(
        "INSERT INTO login_attempts(username, source_ip, timestamp, outcome)"
        " VALUES (?,?,?, 'failure')",
        ("alice", "10.0.0.1", old),
    )
    # A 3600-second window includes the old failure, so four more reach five.
    for _ in range(3):
        assert record_failure(conn, "alice", "10.0.0.1", window_seconds=3600)["locked"] is False
    assert record_failure(conn, "alice", "10.0.0.1", window_seconds=3600)["locked"] is True

    # A 60-second window excludes it: the same four fresh failures stay below 5.
    conn2 = sqlite3.connect(tmp_path / "second.db")
    auth.ensure_schema(conn2)
    ensure_schema(conn2)
    conn2.execute(
        "INSERT INTO login_attempts(username, source_ip, timestamp, outcome)"
        " VALUES (?,?,?, 'failure')",
        ("alice", "10.0.0.1", old),
    )
    for _ in range(4):
        assert record_failure(conn2, "alice", "10.0.0.1", window_seconds=60)["locked"] is False


def test_record_success_clears_this_pairs_failure_run_and_lockout(tmp_path):
    conn = make_db(tmp_path)
    for _ in range(DEFAULT_MAX_FAILURES):
        record_failure(conn, "alice", "10.0.0.1")
    for _ in range(3):
        record_failure(conn, "alice", "10.0.0.2")

    result = record_success(conn, "alice", "10.0.0.1")
    assert result["cleared_failures"] == DEFAULT_MAX_FAILURES
    assert result["cleared_lockout"] is True

    cleared = is_locked_out(conn, "alice", "10.0.0.1")
    assert cleared["locked"] is False and cleared["failure_count"] == 0
    # The other address's failures are untouched.
    other = is_locked_out(conn, "alice", "10.0.0.2")
    assert other["failure_count"] == 3
    assert "login_success" in audit_actions(conn)


def test_record_success_with_nothing_to_clear_is_a_no_op(tmp_path):
    conn = make_db(tmp_path)
    result = record_success(conn, "alice", "10.0.0.1")
    assert result["cleared_failures"] == 0
    assert result["cleared_lockout"] is False


def test_record_failure_rejects_bad_input(tmp_path):
    conn = make_db(tmp_path)
    with pytest.raises(ValueError, match="username"):
        record_failure(conn, "", "10.0.0.1")
    with pytest.raises(ValueError, match="source_ip"):
        record_failure(conn, "alice", "  ")
    with pytest.raises(ValueError, match="max_failures"):
        record_failure(conn, "alice", "10.0.0.1", max_failures=0)
    with pytest.raises(ValueError, match="window_seconds"):
        record_failure(conn, "alice", "10.0.0.1", window_seconds=-1)
    with pytest.raises(ValueError, match="lockout_seconds"):
        record_failure(conn, "alice", "10.0.0.1", lockout_seconds=True)


# --- Administrator clearing and the summary --------------------------------


def test_clear_lockout_by_username(tmp_path):
    conn = make_db(tmp_path)
    for _ in range(DEFAULT_MAX_FAILURES):
        record_failure(conn, "alice", "10.0.0.1")
        record_failure(conn, "alice", "10.0.0.2")
    result = clear_lockout(conn, username="alice", actor="admin")
    assert result["cleared"] == 2
    assert is_locked_out(conn, "alice", "10.0.0.1")["locked"] is False
    assert is_locked_out(conn, "alice", "10.0.0.2")["locked"] is False
    rows = [r for r in auth.list_audit(conn, limit=1000) if r["action"] == "lockout_clear"]
    assert rows and rows[0]["actor"] == "admin"


def test_clear_lockout_by_source_ip_and_by_both(tmp_path):
    conn = make_db(tmp_path)
    for _ in range(DEFAULT_MAX_FAILURES):
        record_failure(conn, "alice", "10.0.0.1")
        record_failure(conn, "bob", "10.0.0.1")
        record_failure(conn, "carol", "10.0.0.9")
    assert clear_lockout(conn, source_ip="10.0.0.1")["cleared"] == 2
    assert is_locked_out(conn, "carol", "10.0.0.9")["locked"] is True
    assert clear_lockout(conn, username="carol", source_ip="10.0.0.9")["cleared"] == 1
    assert is_locked_out(conn, "carol", "10.0.0.9")["locked"] is False


def test_clear_lockout_requires_a_target(tmp_path):
    conn = make_db(tmp_path)
    with pytest.raises(ValueError, match="requires a username"):
        clear_lockout(conn, actor="admin")


def test_clear_lockout_with_no_matching_row_still_audits(tmp_path):
    conn = make_db(tmp_path)
    result = clear_lockout(conn, username="nobody", actor="admin")
    assert result["cleared"] == 0
    assert "lockout_clear" in audit_actions(conn)


def test_lockout_summary_lists_active_lockouts_and_recent_failures(tmp_path):
    conn = make_db(tmp_path)
    for _ in range(DEFAULT_MAX_FAILURES):
        record_failure(conn, "alice", "10.0.0.1")
    record_failure(conn, "bob", "10.0.0.2")

    summary = lockout_summary(conn)
    locked_pairs = {(row["username"], row["source_ip"]) for row in summary["active_lockouts"]}
    assert ("alice", "10.0.0.1") in locked_pairs
    failure_pairs = {(row["username"], row["source_ip"]) for row in summary["recent_failures"]}
    assert ("bob", "10.0.0.2") in failure_pairs
    assert summary["recent_failure_total"] == DEFAULT_MAX_FAILURES + 1
    assert summary["window_seconds"] == DEFAULT_WINDOW_SECONDS


def test_lockout_summary_excludes_expired_lockouts(tmp_path):
    conn = make_db(tmp_path)
    for _ in range(DEFAULT_MAX_FAILURES):
        record_failure(conn, "alice", "10.0.0.1")
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(timespec="microseconds")
    conn.execute("UPDATE lockouts SET locked_until = ?", (past,))
    summary = lockout_summary(conn)
    assert summary["active_lockouts"] == []


# --- MFA enrolment ---------------------------------------------------------


def test_mfa_status_before_enrolment(tmp_path):
    conn = make_db(tmp_path)
    status = mfa_status(conn, "alice")
    assert status == {
        "username": "alice",
        "enrolled": False,
        "enabled": False,
        "pending": False,
        "created_at": "",
        "confirmed_at": "",
        "recovery_codes_remaining": 0,
    }


def test_start_enrolment_returns_secret_uri_and_recovery_codes(tmp_path):
    conn = make_db(tmp_path)
    result = start_enrolment(conn, "alice")
    assert len(result["secret"]) == 32
    assert result["provisioning_uri"].startswith("otpauth://totp/")
    assert result["secret"] in result["provisioning_uri"]
    assert len(result["recovery_codes"]) == RECOVERY_CODE_COUNT
    assert len(set(result["recovery_codes"])) == RECOVERY_CODE_COUNT

    status = mfa_status(conn, "alice")
    assert status["enrolled"] is True
    assert status["enabled"] is False
    assert status["pending"] is True
    assert status["recovery_codes_remaining"] == RECOVERY_CODE_COUNT
    assert "recovery_codes" not in status
    assert "secret" not in status
    assert "mfa_enrol_start" in audit_actions(conn)


def test_recovery_codes_are_stored_only_as_hashes(tmp_path):
    conn = make_db(tmp_path)
    result = start_enrolment(conn, "alice")
    rows = conn.execute(
        "SELECT code_hash FROM mfa_recovery_codes WHERE username = ?", ("alice",)
    ).fetchall()
    stored = {row["code_hash"] for row in rows}
    assert len(stored) == RECOVERY_CODE_COUNT
    for code in result["recovery_codes"]:
        assert code not in stored
        assert len(code) == 19  # four groups of four hex digits plus three dashes
    for digest in stored:
        assert len(digest) == 64  # a SHA-256 hex digest


def test_recovery_codes_are_returned_only_once(tmp_path):
    conn = make_db(tmp_path)
    first = start_enrolment(conn, "alice")
    second = start_enrolment(conn, "alice")
    assert set(first["recovery_codes"]).isdisjoint(second["recovery_codes"])
    # A status read never carries them.
    assert "recovery_codes" not in mfa_status(conn, "alice")


def test_confirm_enrolment_enables_mfa_with_a_valid_code(tmp_path):
    conn = make_db(tmp_path)
    enrolment = start_enrolment(conn, "alice")
    code = now_code(enrolment["secret"])
    status = confirm_enrolment(conn, "alice", code)
    assert status["enabled"] is True
    assert status["pending"] is False
    assert status["confirmed_at"]
    assert "mfa_enrol_confirm" in audit_actions(conn)


def test_confirm_enrolment_refuses_a_code_that_does_not_verify(tmp_path):
    conn = make_db(tmp_path)
    start_enrolment(conn, "alice")
    with pytest.raises(ValueError, match="did not match"):
        confirm_enrolment(conn, "alice", "000000")
    assert mfa_status(conn, "alice")["enabled"] is False
    assert "mfa_enrol_confirm" not in audit_actions(conn)


def test_confirm_enrolment_without_an_enrolment_raises(tmp_path):
    conn = make_db(tmp_path)
    with pytest.raises(ValueError, match="No MFA enrolment"):
        confirm_enrolment(conn, "alice", "123456")


def test_disable_mfa_clears_the_secret_and_recovery_codes(tmp_path):
    conn = make_db(tmp_path)
    enrolment = start_enrolment(conn, "alice")
    confirm_enrolment(conn, "alice", now_code(enrolment["secret"]))

    result = disable_mfa(conn, "alice", actor="admin")
    assert result["disabled"] is True
    assert result["recovery_codes_removed"] == RECOVERY_CODE_COUNT
    assert mfa_status(conn, "alice")["enrolled"] is False
    remaining = conn.execute(
        "SELECT COUNT(*) FROM mfa_recovery_codes WHERE username = ?", ("alice",)
    ).fetchone()[0]
    assert remaining == 0
    assert "mfa_disable" in audit_actions(conn)


def test_disable_mfa_when_not_enrolled_is_a_no_op(tmp_path):
    conn = make_db(tmp_path)
    result = disable_mfa(conn, "alice")
    assert result["disabled"] is False
    assert result["recovery_codes_removed"] == 0
    assert "mfa_disable" not in audit_actions(conn)


# --- Verifying a login code ------------------------------------------------


def enrolled(conn, username):
    enrolment = start_enrolment(conn, username)
    confirm_enrolment(conn, username, now_code(enrolment["secret"]))
    return enrolment


def test_verify_login_code_accepts_a_valid_totp(tmp_path):
    conn = make_db(tmp_path)
    enrolment = enrolled(conn, "alice")
    result = verify_login_code(conn, "alice", now_code(enrolment["secret"]))
    assert result["valid"] is True
    assert result["method"] == "totp"
    assert result["recovery_codes_remaining"] == RECOVERY_CODE_COUNT
    assert "mfa_login" in audit_actions(conn)


def test_verify_login_code_accepts_and_consumes_a_recovery_code(tmp_path):
    conn = make_db(tmp_path)
    enrolment = enrolled(conn, "alice")
    recovery = enrolment["recovery_codes"][0]

    first = verify_login_code(conn, "alice", recovery)
    assert first["valid"] is True
    assert first["method"] == "recovery_code"
    assert first["recovery_codes_remaining"] == RECOVERY_CODE_COUNT - 1
    assert "mfa_recovery_used" in audit_actions(conn)

    # The same recovery code is refused the second time.
    second = verify_login_code(conn, "alice", recovery)
    assert second["valid"] is False
    assert second["recovery_codes_remaining"] == RECOVERY_CODE_COUNT - 1


def test_verify_login_code_accepts_a_recovery_code_without_dashes(tmp_path):
    conn = make_db(tmp_path)
    enrolment = enrolled(conn, "alice")
    recovery = enrolment["recovery_codes"][0].replace("-", "").lower()
    assert verify_login_code(conn, "alice", recovery)["valid"] is True


def test_verify_login_code_rejects_a_wrong_code(tmp_path):
    conn = make_db(tmp_path)
    enrolled(conn, "alice")
    result = verify_login_code(conn, "alice", "000000")
    assert result["valid"] is False
    assert result["method"] is None
    assert result["enabled"] is True
    assert "mfa_login_failed" in audit_actions(conn)


def test_verify_login_code_when_mfa_is_not_enabled(tmp_path):
    conn = make_db(tmp_path)
    result = verify_login_code(conn, "alice", "123456")
    assert result["valid"] is False
    assert result["enabled"] is False
    assert result["reason"] == "multi-factor authentication is not enabled"


def test_verify_login_code_is_false_for_a_pending_enrolment(tmp_path):
    conn = make_db(tmp_path)
    start_enrolment(conn, "alice")  # not confirmed
    assert verify_login_code(conn, "alice", "123456")["valid"] is False


# --- Schema ----------------------------------------------------------------


def test_ensure_schema_is_idempotent(tmp_path):
    conn = make_db(tmp_path)
    ensure_schema(conn)
    ensure_schema(conn)
    assert is_locked_out(conn, "alice", "10.0.0.1")["locked"] is False
    assert mfa_status(conn, "alice")["enrolled"] is False
