"""Accounts, roles, sessions, and the audit trail must behave as documented."""
import io
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import pytest

from src.auth import (
    ACTIONS,
    PASSWORD_ENV_VAR,
    PASSWORD_MIN_LENGTH,
    PERMISSIONS,
    ROLES,
    SCRYPT_DKLEN,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
    authenticate,
    check_password_policy,
    create_session,
    create_user,
    delete_user,
    ensure_schema,
    has_permission,
    list_audit,
    list_users,
    main,
    purge_expired_sessions,
    record_audit,
    revoke_session,
    revoke_user_sessions,
    set_enabled,
    set_password,
    set_role,
    validate_session,
)

GOOD = "correct horse 42"  # 16 chars, a letter and a digit


def make_db(tmp_path):
    conn = sqlite3.connect(tmp_path / "auth.db")
    ensure_schema(conn)
    return conn


def raw_user(conn, username):
    return conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def audit_actions(conn):
    return [row["action"] for row in list_audit(conn, limit=1000)]


# --- Schema, roles, permissions -------------------------------------------


def test_schema_can_be_created_twice(tmp_path):
    conn = make_db(tmp_path)
    ensure_schema(conn)
    assert list_users(conn) == []


def test_roles_and_actions_are_the_documented_ones():
    assert ROLES == ("viewer", "analyst", "admin")
    assert set(ACTIONS) == {
        "view_events",
        "view_hosts",
        "triage_detection",
        "manage_suppressions",
        "manage_users",
        "view_audit",
        "export_data",
    }


def test_permission_matrix_is_explicit():
    assert set(PERMISSIONS) == set(ROLES)
    assert PERMISSIONS["viewer"] == frozenset({"view_events", "view_hosts"})
    assert PERMISSIONS["analyst"] == frozenset(
        {"view_events", "view_hosts", "triage_detection", "manage_suppressions", "export_data"}
    )
    assert PERMISSIONS["admin"] == frozenset(ACTIONS)


def test_has_permission_allows_and_denies():
    assert has_permission("viewer", "view_events") is True
    assert has_permission("viewer", "manage_users") is False
    assert has_permission("analyst", "triage_detection") is True
    assert has_permission("analyst", "view_audit") is False
    assert has_permission("admin", "manage_users") is True
    assert has_permission("admin", "view_audit") is True


def test_has_permission_denies_unknown_role_but_rejects_unknown_action():
    assert has_permission("nobody", "view_events") is False
    with pytest.raises(ValueError, match="Unknown action"):
        has_permission("viewer", "not_an_action")


# --- Creating users --------------------------------------------------------


def test_create_user_returns_public_fields_without_secrets(tmp_path):
    conn = make_db(tmp_path)
    user = create_user(conn, "Alice", GOOD, "analyst")
    assert user["username"] == "Alice"
    assert user["role"] == "analyst"
    assert user["enabled"] is True
    assert user["last_login_at"] == ""
    assert user["created_at"]
    assert "password_hash" not in user and "salt" not in user


def test_create_user_stores_scrypt_parameters_per_user(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "alice", GOOD, "viewer")
    row = raw_user(conn, "alice")
    assert row["password_hash"] != GOOD
    assert len(bytes.fromhex(row["salt"])) == 16
    assert (row["scrypt_n"], row["scrypt_r"], row["scrypt_p"], row["scrypt_dklen"]) == (
        SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN
    )


def test_hashes_are_salted_per_user(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "alice", "SamePassword123", "viewer")
    create_user(conn, "bob", "SamePassword123", "viewer")
    assert raw_user(conn, "alice")["salt"] != raw_user(conn, "bob")["salt"]
    assert raw_user(conn, "alice")["password_hash"] != raw_user(conn, "bob")["password_hash"]


def test_create_user_rejects_weak_password_listing_every_problem(tmp_path):
    conn = make_db(tmp_path)
    with pytest.raises(ValueError) as excinfo:
        create_user(conn, "alice", "12345", "viewer")
    message = str(excinfo.value)
    assert "at least 12 characters" in message and "at least one letter" in message
    assert list_users(conn) == []


def test_check_password_policy_reports_each_rule():
    assert check_password_policy(GOOD) == []
    assert len(check_password_policy("abc", "x")) == 2  # length + digit
    assert check_password_policy("alllettershere", "x") == ["must contain at least one digit"]
    assert check_password_policy("123456789012", "x") == ["must contain at least one letter"]
    assert "must not contain the username" in check_password_policy("AdminPassword12", "admin")
    assert check_password_policy("   ", "x") == [
        "must be at least 12 characters long",
        "must contain at least one letter",
        "must contain at least one digit",
        "must not be empty or only whitespace",
    ]


def test_create_user_rejects_duplicate_username_case_insensitively(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "Alice", GOOD, "viewer")
    with pytest.raises(ValueError, match="already exists"):
        create_user(conn, "alice", GOOD, "viewer")


def test_create_user_rejects_unknown_role_and_bad_username(tmp_path):
    conn = make_db(tmp_path)
    with pytest.raises(ValueError, match="Unknown role"):
        create_user(conn, "alice", GOOD, "superuser")
    with pytest.raises(ValueError, match="username may contain only"):
        create_user(conn, "bad name", GOOD, "viewer")
    with pytest.raises(ValueError, match="must not be empty"):
        create_user(conn, "   ", GOOD, "viewer")


# --- Authentication --------------------------------------------------------


def test_authenticate_accepts_correct_password_any_username_case(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "Alice", GOOD, "analyst")
    found = authenticate(conn, "alice", GOOD)
    assert found is not None
    assert found["username"] == "Alice"
    assert found["role"] == "analyst"


def test_authenticate_rejects_wrong_password_and_unknown_user(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "alice", GOOD, "viewer")
    assert authenticate(conn, "alice", "wrong password 1") is None
    assert authenticate(conn, "nobody", GOOD) is None


def test_authenticate_records_last_login(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "alice", GOOD, "viewer")
    found = authenticate(conn, "alice", GOOD)
    assert found["last_login_at"]
    assert raw_user(conn, "alice")["last_login_at"] == found["last_login_at"]


def test_authenticate_fails_closed_on_bad_input(tmp_path):
    conn = make_db(tmp_path)
    assert authenticate(conn, "", GOOD) is None
    assert authenticate(conn, None, GOOD) is None
    assert authenticate(conn, "alice", None) is None


def test_authenticate_refuses_disabled_account(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "alice", GOOD, "viewer")
    create_user(conn, "root", GOOD, "admin")
    set_enabled(conn, "alice", False, actor="root")
    assert authenticate(conn, "alice", GOOD) is None


# --- Changing users --------------------------------------------------------


def test_set_password_changes_the_password_and_rejects_weak(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "alice", GOOD, "viewer")
    old_salt = raw_user(conn, "alice")["salt"]
    set_password(conn, "alice", "BrandNewPass99")
    assert authenticate(conn, "alice", GOOD) is None
    assert authenticate(conn, "alice", "BrandNewPass99") is not None
    assert raw_user(conn, "alice")["salt"] != old_salt
    with pytest.raises(ValueError, match="policy"):
        set_password(conn, "alice", "weak")
    with pytest.raises(ValueError, match="Unknown user"):
        set_password(conn, "ghost", GOOD)


def test_set_role_changes_role_and_refuses_unknown(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "root", GOOD, "admin")
    create_user(conn, "alice", GOOD, "viewer")
    updated = set_role(conn, "alice", "analyst", actor="root")
    assert updated["role"] == "analyst"
    with pytest.raises(ValueError, match="Unknown role"):
        set_role(conn, "alice", "superuser")
    with pytest.raises(ValueError, match="Unknown user"):
        set_role(conn, "ghost", "admin")


def test_set_role_refuses_to_demote_last_admin(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "root", GOOD, "admin")
    with pytest.raises(ValueError, match="last enabled administrator"):
        set_role(conn, "root", "viewer")
    create_user(conn, "root2", GOOD, "admin")
    assert set_role(conn, "root", "viewer")["role"] == "viewer"


def test_set_enabled_toggles_and_requires_boolean(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "root", GOOD, "admin")
    create_user(conn, "alice", GOOD, "viewer")
    assert set_enabled(conn, "alice", False)["enabled"] is False
    assert set_enabled(conn, "alice", True)["enabled"] is True
    with pytest.raises(ValueError, match="true or false"):
        set_enabled(conn, "alice", "yes")
    with pytest.raises(ValueError, match="Unknown user"):
        set_enabled(conn, "ghost", False)


def test_set_enabled_refuses_to_disable_last_admin(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "root", GOOD, "admin")
    with pytest.raises(ValueError, match="last enabled administrator"):
        set_enabled(conn, "root", False)


def test_delete_user_refuses_last_admin_and_works_for_others(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "root", GOOD, "admin")
    with pytest.raises(ValueError, match="last enabled administrator"):
        delete_user(conn, "root")
    create_user(conn, "alice", GOOD, "viewer")
    removed = delete_user(conn, "alice", actor="root")
    assert removed["username"] == "alice"
    assert [u["username"] for u in list_users(conn)] == ["root"]
    with pytest.raises(ValueError, match="Unknown user"):
        delete_user(conn, "alice")


def test_delete_user_removes_its_sessions(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "root", GOOD, "admin")
    create_user(conn, "alice", GOOD, "viewer")
    session = create_session(conn, "alice", 3600)
    delete_user(conn, "alice", actor="root")
    assert validate_session(conn, session["token"]) is None
    # recreating the same username must not inherit the old session
    create_user(conn, "alice", GOOD, "viewer")
    assert validate_session(conn, session["token"]) is None


def test_list_users_is_sorted_and_secret_free(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "carol", GOOD, "viewer")
    create_user(conn, "alice", GOOD, "viewer")
    create_user(conn, "bob", GOOD, "viewer")
    names = [user["username"] for user in list_users(conn)]
    assert names == ["alice", "bob", "carol"]
    assert all(set(user) == {"username", "role", "created_at", "last_login_at", "enabled"} for user in list_users(conn))


# --- Sessions --------------------------------------------------------------


def test_create_session_returns_token_and_stores_only_a_hash(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "alice", GOOD, "viewer")
    session = create_session(conn, "alice", 3600)
    token = session["token"]
    assert token and len(token) >= 32
    row = conn.execute("SELECT * FROM sessions").fetchone()
    assert row["token_hash"] != token
    assert len(row["token_hash"]) == 64
    assert row["username"] == "alice"
    assert row["revoked"] == 0


def test_create_session_rejects_bad_ttl_and_unknown_or_disabled_user(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "root", GOOD, "admin")
    create_user(conn, "alice", GOOD, "viewer")
    for bad in (0, -5, "soon"):
        with pytest.raises(ValueError):
            create_session(conn, "alice", bad)
    with pytest.raises(ValueError, match="Unknown user"):
        create_session(conn, "ghost", 3600)
    set_enabled(conn, "alice", False, actor="root")
    with pytest.raises(ValueError, match="disabled user"):
        create_session(conn, "alice", 3600)


def test_validate_session_accepts_live_token(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "alice", GOOD, "analyst")
    session = create_session(conn, "alice", 3600)
    found = validate_session(conn, session["token"])
    assert found["username"] == "alice"
    assert found["role"] == "analyst"
    assert found["expires_at"] == session["expires_at"]
    assert "token" not in found and "token_hash" not in found


def test_validate_session_honours_expiry(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "alice", GOOD, "viewer")
    session = create_session(conn, "alice", 3600)
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(timespec="microseconds")
    conn.execute("UPDATE sessions SET expires_at = ?", (past,))
    assert validate_session(conn, session["token"]) is None
    assert validate_session(conn, "not-a-real-token") is None
    assert validate_session(conn, "") is None


def test_validate_session_honours_revocation_and_disabled_user(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "root", GOOD, "admin")
    create_user(conn, "alice", GOOD, "viewer")
    revoked = create_session(conn, "alice", 3600)
    revoke_session(conn, revoked["token"], actor="root")
    assert validate_session(conn, revoked["token"]) is None

    disabled = create_session(conn, "alice", 3600)
    set_enabled(conn, "alice", False, actor="root")
    assert validate_session(conn, disabled["token"]) is None


def test_revoke_session_is_idempotent_and_rejects_unknown(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "alice", GOOD, "viewer")
    session = create_session(conn, "alice", 3600)
    first = revoke_session(conn, session["token"])
    assert first["revoked"] is True
    assert revoke_session(conn, session["token"])["revoked"] is True
    with pytest.raises(ValueError, match="Unknown session token"):
        revoke_session(conn, "nope")
    with pytest.raises(ValueError, match="token is required"):
        revoke_session(conn, "")


def test_revoke_user_sessions_counts_and_invalidates(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "alice", GOOD, "viewer")
    a = create_session(conn, "alice", 3600)
    b = create_session(conn, "alice", 3600)
    assert revoke_user_sessions(conn, "alice") == 2
    assert validate_session(conn, a["token"]) is None
    assert validate_session(conn, b["token"]) is None
    assert revoke_user_sessions(conn, "alice") == 0
    with pytest.raises(ValueError, match="Unknown user"):
        revoke_user_sessions(conn, "ghost")


def test_purge_expired_sessions_removes_dead_rows(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "alice", GOOD, "viewer")
    live = create_session(conn, "alice", 3600)
    dead = create_session(conn, "alice", 3600)
    revoke_session(conn, dead["token"])
    assert purge_expired_sessions(conn) == 1
    assert validate_session(conn, live["token"]) is not None
    assert validate_session(conn, dead["token"]) is None


# --- Audit trail -----------------------------------------------------------


def test_record_audit_validates_actor_and_action_and_serialises_detail(tmp_path):
    conn = make_db(tmp_path)
    row = record_audit(conn, "alice", "custom", "target", {"b": 2, "a": 1})
    assert row["actor"] == "alice" and row["action"] == "custom"
    assert json.loads(row["detail"]) == {"a": 1, "b": 2}
    with pytest.raises(ValueError, match="actor must be"):
        record_audit(conn, "", "x")
    with pytest.raises(ValueError, match="action must be"):
        record_audit(conn, "a", "  ")


def test_every_mutating_function_writes_an_audit_row(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "root", GOOD, "admin")
    create_user(conn, "alice", GOOD, "viewer")
    authenticate(conn, "alice", "wrong password 1")
    authenticate(conn, "alice", GOOD)
    set_password(conn, "alice", "AnotherPass123")
    set_role(conn, "alice", "analyst", actor="root")
    set_enabled(conn, "alice", False, actor="root")
    set_enabled(conn, "alice", True, actor="root")
    session = create_session(conn, "alice", 3600)
    revoke_session(conn, session["token"], actor="root")
    revoke_user_sessions(conn, "alice", actor="root")
    purge_expired_sessions(conn)
    delete_user(conn, "alice", actor="root")

    actions = set(audit_actions(conn))
    assert {
        "user_create",
        "login_failed",
        "login",
        "password_change",
        "role_change",
        "user_disable",
        "user_enable",
        "session_create",
        "session_revoke",
        "session_revoke_user",
        "session_purge",
        "user_delete",
    } <= actions


def test_failed_login_is_audited(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "alice", GOOD, "viewer")
    authenticate(conn, "alice", "wrong password 1")
    authenticate(conn, "ghost", GOOD)
    rows = [row for row in list_audit(conn, limit=1000) if row["action"] == "login_failed"]
    assert len(rows) == 2


def test_no_op_changes_write_no_audit_row(tmp_path):
    conn = make_db(tmp_path)
    create_user(conn, "root", GOOD, "admin")
    create_user(conn, "alice", GOOD, "viewer")
    before = len(audit_actions(conn))
    set_role(conn, "alice", "viewer")
    set_enabled(conn, "alice", True)
    assert len(audit_actions(conn)) == before


def test_list_audit_pages_newest_first_and_clamps_limit(tmp_path):
    conn = make_db(tmp_path)
    for index in range(5):
        record_audit(conn, "tester", f"action{index}")
    newest = list_audit(conn, limit=2)
    assert [row["action"] for row in newest] == ["action4", "action3"]
    second = list_audit(conn, limit=2, offset=2)
    assert [row["action"] for row in second] == ["action2", "action1"]
    assert len(list_audit(conn, limit=0)) == 1  # clamped up to one
    with pytest.raises(ValueError, match="whole numbers"):
        list_audit(conn, limit="lots")


# --- Command line ----------------------------------------------------------


def test_cli_creates_admin_from_environment(tmp_path, monkeypatch, capsys):
    db = tmp_path / "cli.db"
    monkeypatch.setenv(PASSWORD_ENV_VAR, "BootstrapPass123")
    assert main(["--init-admin", "root", "--db", str(db)]) == 0
    assert "root" in capsys.readouterr().out

    conn = sqlite3.connect(db)
    ensure_schema(conn)
    found = authenticate(conn, "root", "BootstrapPass123")
    assert found["role"] == "admin"


def test_cli_creates_admin_from_stdin(tmp_path, monkeypatch, capsys):
    db = tmp_path / "cli.db"
    monkeypatch.delenv(PASSWORD_ENV_VAR, raising=False)
    monkeypatch.setattr(sys, "stdin", io.StringIO("PipedPassword123\n"))
    assert main(["--init-admin", "root", "--db", str(db)]) == 0

    conn = sqlite3.connect(db)
    ensure_schema(conn)
    assert authenticate(conn, "root", "PipedPassword123") is not None


def test_cli_rejects_duplicate_and_weak_password(tmp_path, monkeypatch, capsys):
    db = tmp_path / "cli.db"
    monkeypatch.setenv(PASSWORD_ENV_VAR, "BootstrapPass123")
    assert main(["--init-admin", "root", "--db", str(db)]) == 0
    assert main(["--init-admin", "root", "--db", str(db)]) == 1
    monkeypatch.setenv(PASSWORD_ENV_VAR, "weak")
    assert main(["--init-admin", "other", "--db", str(db)]) == 1
    assert "policy" in capsys.readouterr().err


def test_cli_reports_missing_password(tmp_path, monkeypatch, capsys):
    db = tmp_path / "cli.db"
    monkeypatch.delenv(PASSWORD_ENV_VAR, raising=False)
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert main(["--init-admin", "root", "--db", str(db)]) == 1
    assert PASSWORD_ENV_VAR in capsys.readouterr().err


def test_cli_refuses_a_password_on_the_command_line(tmp_path):
    with pytest.raises(SystemExit):
        main(["--init-admin", "root", "--db", str(tmp_path / "cli.db"), "--password", "secret"])
