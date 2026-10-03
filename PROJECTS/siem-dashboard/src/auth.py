"""Accounts, roles, sessions, and an audit trail for the local SIEM console.

The console had no notion of a user: any request that reached it could read every
event, and the only access control was an optional shared token. This module adds
real accounts, a role/permission matrix, hashed session tokens, and an audit log,
stored in the same SQLite file as the events.

What this module guarantees
---------------------------
* Passwords are hashed with ``hashlib.scrypt`` from the standard library, with a
  fresh ``secrets``-generated salt per user. The cost parameters are stored on
  each row, so they can be raised later without invalidating existing hashes: an
  old row keeps verifying with the parameters it was written with.
* Password hashes and salts never leave the module. No function here returns
  them, so a caller cannot accidentally serialise a hash into an API response.
* Session tokens are generated with ``secrets`` and only their SHA-256 hash is
  stored. A copy of the database does not contain a usable token. The plaintext
  token is returned once, by ``create_session``.
* The audit log records who did what. Every function that changes stored state
  writes a row, and both successful and failed logins are recorded. A setter
  called with the value a row already holds changes nothing and writes nothing;
  the maintenance calls (purge, revoke-all) always record what they found.

What this module does NOT do
----------------------------
* It does not enforce anything. ``has_permission`` answers a question; the
  caller (the HTTP layer) must ask it before serving a route. A route that
  forgets to check is not protected by this module.
* There is no TLS. This is a local application. If the console is bound to
  anything other than localhost, passwords and session tokens cross the network
  in cleartext, and a session cookie or bearer token is only as safe as the
  transport that carries it.
* The audit log is append-only by convention, not by construction. SQLite does
  not stop a caller from rewriting it, and it is not signed, so it is not
  tamper-evident.
* There is no login rate limit, lockout, or multi-factor authentication. The
  only brake on guessing is the scrypt cost, roughly 0.18 seconds per attempt at
  the default parameters on the development machine.
* The password policy is length and composition only. It cannot tell a strong
  password from a long weak one.
* An unknown username is verified against a dummy hash so the response time does
  not obviously reveal whether an account exists. That is a mitigation, not a
  proof.

Parameters
----------
``scrypt`` is used at N=2**14, r=8, p=1, dklen=64. N=2**14 with r=8 is the
interactive-login setting from the scrypt paper: about 16 MiB of memory and
about 0.18 s per verification here, which is affordable for a login and costly
for an offline attacker. A larger N (2**15 or 2**16) can be used for new hashes
later by changing ``SCRYPT_N``; existing users keep verifying because their
parameters are read from their own row.

Timestamps are ISO-8601 UTC strings with microseconds, so they compare correctly
as text and parse back with ``datetime.fromisoformat``.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# --- Roles and permissions -------------------------------------------------

ROLES: tuple[str, ...] = ("viewer", "analyst", "admin")

# Every action the console can ask about. The names are the vocabulary the HTTP
# layer checks; a route maps to exactly one of these.
ACTIONS: tuple[str, ...] = (
    "view_events",
    "view_hosts",
    "triage_detection",
    "manage_suppressions",
    "manage_users",
    "view_audit",
    "export_data",
)

# The matrix. A viewer watches; an analyst works the queue but cannot change who
# can log in or read the audit trail; an admin does everything. This is the only
# place authority is defined, so there is one line to read to answer "can this
# role do this".
PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"view_events", "view_hosts"}),
    "analyst": frozenset(
        {
            "view_events",
            "view_hosts",
            "triage_detection",
            "manage_suppressions",
            "export_data",
        }
    ),
    "admin": frozenset(ACTIONS),
}

# --- Password hashing parameters -------------------------------------------

# Chosen for interactive logins; see the module docstring. Stored per user, so
# changing these values affects only newly written hashes.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64
SALT_BYTES = 16

# --- Password policy -------------------------------------------------------

PASSWORD_MIN_LENGTH = 12

# --- Sessions --------------------------------------------------------------

SESSION_TOKEN_BYTES = 32
DEFAULT_SESSION_TTL_SECONDS = 12 * 60 * 60  # 12 hours

# --- Audit -----------------------------------------------------------------

AUDIT_LIMIT_DEFAULT = 100
AUDIT_LIMIT_MAX = 1000

# --- CLI -------------------------------------------------------------------

# The bootstrap password is read from this environment variable, or from stdin.
# It is never accepted as a command-line argument, which would land in shell
# history and in the process table.
PASSWORD_ENV_VAR = "SIEM_ADMIN_PASSWORD"

_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")

_SCHEMA: tuple[str, ...] = (
    # username is COLLATE NOCASE so both the unique constraint and every lookup
    # are case-insensitive: "Alice" and "alice" are the same account.
    """
    CREATE TABLE IF NOT EXISTS users (
        username TEXT NOT NULL COLLATE NOCASE PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        scrypt_n INTEGER NOT NULL,
        scrypt_r INTEGER NOT NULL,
        scrypt_p INTEGER NOT NULL,
        scrypt_dklen INTEGER NOT NULL,
        role TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_login_at TEXT,
        enabled INTEGER NOT NULL DEFAULT 1
    )
    """,
    # Only the hash of a session token is stored, never the token itself.
    """
    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_sessions_username ON sessions(username)",
    "CREATE INDEX IF NOT EXISTS ix_audit_log_timestamp ON audit_log(timestamp)",
)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the auth tables if they are not already present.

    Idempotent, so a caller can run it on every startup. It also sets the
    connection's row factory to ``sqlite3.Row`` so the rows this module returns
    can be read by column name; ``sqlite3.Row`` still supports positional access,
    so this does not break a caller that indexes rows by number.
    """

    conn.row_factory = sqlite3.Row
    for statement in _SCHEMA:
        conn.execute(statement)


# --- Time helpers ----------------------------------------------------------


def _utc_now() -> str:
    """An ISO-8601 UTC timestamp with microseconds, so text compares correctly."""

    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _parse_iso(value: Any) -> datetime | None:
    """Parse a stored timestamp, treating a naive value as UTC."""

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


# --- Permission checks -----------------------------------------------------


def has_permission(role: str, action: str) -> bool:
    """Whether ``role`` may perform ``action``.

    An unknown action raises ``ValueError``: actions come from our own call
    sites, so a misspelt one is a programming error that should fail loudly
    rather than silently deny. An unknown role returns ``False``: roles come
    from the database, which a caller could corrupt, and a guard should deny by
    default instead of turning a bad row into a 500.
    """

    if action not in ACTIONS:
        raise ValueError(
            f"Unknown action {action!r}. Expected one of: {', '.join(ACTIONS)}."
        )
    return action in PERMISSIONS.get(role, frozenset())


# --- Password hashing ------------------------------------------------------


def _maxmem(n: int, r: int) -> int:
    """The memory scrypt may use for these parameters, with headroom.

    scrypt needs 128*n*r bytes; OpenSSL refuses to allocate unless ``maxmem``
    exceeds it. Doubling leaves room and keeps a raised N working.
    """

    return 128 * n * r * 2


def _hash_password(
    password: str,
    *,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
    dklen: int = SCRYPT_DKLEN,
    salt: bytes | None = None,
) -> tuple[str, str]:
    """Return ``(salt_hex, hash_hex)`` for a password.

    A fresh random salt is used unless one is supplied, which only the tests do.
    """

    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=dklen,
        maxmem=_maxmem(n, r),
    )
    return salt.hex(), derived.hex()


def _verify_password(password: str, row: sqlite3.Row) -> bool:
    """Constant-time check of ``password`` against a stored user row.

    A row whose parameters or encodings are corrupt fails the check rather than
    raising, because an unreadable hash must not become an authenticated login.
    """

    try:
        salt = bytes.fromhex(str(row["salt"]))
        expected = bytes.fromhex(str(row["password_hash"]))
        n = int(row["scrypt_n"])
        r = int(row["scrypt_r"])
        p = int(row["scrypt_p"])
        dklen = int(row["scrypt_dklen"])
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=dklen,
            maxmem=_maxmem(n, r),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(derived, expected)


def _dummy_verify(password: str) -> None:
    """Spend the same work as a real verification, for an unknown username.

    Without this, a missing account would answer almost instantly while a real
    one took ~0.18 s, which leaks which usernames exist.
    """

    text = password if isinstance(password, str) else ""
    try:
        hashlib.scrypt(
            text.encode("utf-8"),
            salt=secrets.token_bytes(SALT_BYTES),
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_DKLEN,
            maxmem=_maxmem(SCRYPT_N, SCRYPT_R),
        )
    except ValueError:  # pragma: no cover - defensive, parameters are valid
        pass


def check_password_policy(password: str, username: str = "") -> list[str]:
    """Every policy rule ``password`` breaks, as short human-readable phrases.

    Returns an empty list when the password is acceptable. The rules are: at
    least ``PASSWORD_MIN_LENGTH`` characters, at least one letter, at least one
    digit, not empty or all whitespace, and not containing the username.
    """

    if not isinstance(password, str):
        return ["must be text"]

    problems: list[str] = []
    if len(password) < PASSWORD_MIN_LENGTH:
        problems.append(f"must be at least {PASSWORD_MIN_LENGTH} characters long")
    if not any(character.isalpha() for character in password):
        problems.append("must contain at least one letter")
    if not any(character.isdigit() for character in password):
        problems.append("must contain at least one digit")
    if password.strip() == "":
        problems.append("must not be empty or only whitespace")
    if username and len(str(username)) >= 3 and str(username).lower() in password.lower():
        problems.append("must not contain the username")
    return problems


def _enforce_password_policy(password: str, username: str) -> None:
    """Raise ``ValueError`` listing every rule the password breaks."""

    problems = check_password_policy(password, username)
    if problems:
        raise ValueError(
            "Password does not meet the policy: " + "; ".join(problems) + "."
        )


# --- Row helpers -----------------------------------------------------------


def _public_user(row: sqlite3.Row) -> dict[str, Any]:
    """A user as the rest of the application sees it.

    Deliberately omits the hash, salt, and parameters: those never leave this
    module.
    """

    return {
        "username": str(row["username"]),
        "role": str(row["role"]),
        "created_at": str(row["created_at"]),
        "last_login_at": row["last_login_at"] or "",
        "enabled": bool(row["enabled"]),
    }


def _get_user(conn: sqlite3.Connection, username: Any) -> sqlite3.Row | None:
    if not isinstance(username, str) or not username.strip():
        return None
    return conn.execute(
        "SELECT * FROM users WHERE username = ?", (username.strip(),)
    ).fetchone()


def _validate_username(username: Any) -> str:
    if not isinstance(username, str):
        raise ValueError("username must be a string")
    clean = username.strip()
    if not clean:
        raise ValueError("username must not be empty")
    if not _USERNAME_PATTERN.match(clean):
        raise ValueError(
            "username may contain only letters, digits, and . _ @ - "
            "(up to 64 characters)"
        )
    return clean


def _enabled_admin_count(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND enabled = 1"
    ).fetchone()
    return int(row["count"])


def _is_last_enabled_admin(conn: sqlite3.Connection, username: str) -> bool:
    """Whether ``username`` is the only enabled administrator left."""

    row = _get_user(conn, username)
    if row is None or str(row["role"]) != "admin" or not bool(row["enabled"]):
        return False
    return _enabled_admin_count(conn) <= 1


# --- Users -----------------------------------------------------------------


def create_user(
    conn: sqlite3.Connection,
    username: str,
    password: str,
    role: str,
    *,
    actor: str | None = None,
) -> dict[str, Any]:
    """Create an account and return it as a public dict.

    ``actor`` is who is performing the change, for the audit trail; it defaults
    to the new username, which is right for a self-service sign-up and wrong for
    an administrator creating someone else, so the caller should pass it there.
    """

    clean = _validate_username(username)
    if role not in ROLES:
        raise ValueError(f"Unknown role {role!r}. Expected one of: {', '.join(ROLES)}.")
    _enforce_password_policy(password, clean)
    if _get_user(conn, clean) is not None:
        raise ValueError(f"User {clean!r} already exists.")

    salt_hex, hash_hex = _hash_password(password)
    created = _utc_now()
    try:
        conn.execute(
            "INSERT INTO users("
            " username, password_hash, salt, scrypt_n, scrypt_r, scrypt_p,"
            " scrypt_dklen, role, created_at, last_login_at, enabled"
            ") VALUES (?,?,?,?,?,?,?,?,?,NULL,1)",
            (
                clean,
                hash_hex,
                salt_hex,
                SCRYPT_N,
                SCRYPT_R,
                SCRYPT_P,
                SCRYPT_DKLEN,
                role,
                created,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"User {clean!r} already exists.") from exc

    record_audit(conn, actor or clean, "user_create", clean, {"role": role})
    return _public_user(_get_user(conn, clean))


def authenticate(
    conn: sqlite3.Connection,
    username: str,
    password: str,
) -> dict[str, Any] | None:
    """Return the user when the password matches, otherwise ``None``.

    Malformed input fails closed (``None``) rather than raising, so a login path
    cannot turn a bad request into an error that a caller might treat as
    success. A successful login updates ``last_login_at``. Both success and
    failure are written to the audit log.
    """

    if not isinstance(username, str) or not isinstance(password, str) or not username.strip():
        return None

    row = _get_user(conn, username)
    if row is None:
        _dummy_verify(password)
        record_audit(conn, username.strip(), "login_failed", username.strip(), "unknown user")
        return None

    name = str(row["username"])
    if not _verify_password(password, row):
        record_audit(conn, name, "login_failed", name, "bad password")
        return None
    if not bool(row["enabled"]):
        record_audit(conn, name, "login_failed", name, "account disabled")
        return None

    conn.execute(
        "UPDATE users SET last_login_at = ? WHERE username = ?", (_utc_now(), name)
    )
    record_audit(conn, name, "login", name)
    return _public_user(_get_user(conn, name))


def set_password(
    conn: sqlite3.Connection,
    username: str,
    password: str,
    *,
    actor: str | None = None,
) -> dict[str, Any]:
    """Replace a user's password, with a new salt and the current parameters."""

    row = _get_user(conn, username)
    if row is None:
        raise ValueError(f"Unknown user {username!r}.")
    name = str(row["username"])
    _enforce_password_policy(password, name)

    salt_hex, hash_hex = _hash_password(password)
    conn.execute(
        "UPDATE users SET password_hash = ?, salt = ?, scrypt_n = ?, scrypt_r = ?,"
        " scrypt_p = ?, scrypt_dklen = ? WHERE username = ?",
        (hash_hex, salt_hex, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN, name),
    )
    record_audit(conn, actor or name, "password_change", name)
    return _public_user(_get_user(conn, name))


def set_role(
    conn: sqlite3.Connection,
    username: str,
    role: str,
    *,
    actor: str | None = None,
) -> dict[str, Any]:
    """Change a user's role.

    Refuses to demote the last enabled administrator, so the console cannot be
    locked out of its own user management.
    """

    if role not in ROLES:
        raise ValueError(f"Unknown role {role!r}. Expected one of: {', '.join(ROLES)}.")
    row = _get_user(conn, username)
    if row is None:
        raise ValueError(f"Unknown user {username!r}.")
    name = str(row["username"])
    current = str(row["role"])
    if current == role:
        return _public_user(row)
    if role != "admin" and _is_last_enabled_admin(conn, name):
        raise ValueError("Cannot change the role of the last enabled administrator.")

    conn.execute("UPDATE users SET role = ? WHERE username = ?", (role, name))
    record_audit(conn, actor or name, "role_change", name, {"from": current, "to": role})
    return _public_user(_get_user(conn, name))


def set_enabled(
    conn: sqlite3.Connection,
    username: str,
    enabled: bool,
    *,
    actor: str | None = None,
) -> dict[str, Any]:
    """Enable or disable an account.

    Refuses to disable the last enabled administrator, for the same reason
    ``set_role`` refuses to demote them.
    """

    if not isinstance(enabled, bool):
        raise ValueError("enabled must be true or false")
    row = _get_user(conn, username)
    if row is None:
        raise ValueError(f"Unknown user {username!r}.")
    name = str(row["username"])
    current = bool(row["enabled"])
    if current == enabled:
        return _public_user(row)
    if not enabled and _is_last_enabled_admin(conn, name):
        raise ValueError("Cannot disable the last enabled administrator.")

    conn.execute(
        "UPDATE users SET enabled = ? WHERE username = ?", (1 if enabled else 0, name)
    )
    record_audit(
        conn, actor or name, "user_enable" if enabled else "user_disable", name
    )
    return _public_user(_get_user(conn, name))


def list_users(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Every account, newest-first by name, without any secret material."""

    rows = conn.execute(
        "SELECT * FROM users ORDER BY username COLLATE NOCASE ASC"
    ).fetchall()
    return [_public_user(row) for row in rows]


def delete_user(
    conn: sqlite3.Connection,
    username: str,
    *,
    actor: str | None = None,
) -> dict[str, Any]:
    """Delete an account and return it as it was.

    Refuses to delete the last enabled administrator. The account's sessions are
    deleted with it, so recreating the same username later cannot inherit them.
    """

    row = _get_user(conn, username)
    if row is None:
        raise ValueError(f"Unknown user {username!r}.")
    name = str(row["username"])
    if _is_last_enabled_admin(conn, name):
        raise ValueError("Cannot delete the last enabled administrator.")

    conn.execute("DELETE FROM sessions WHERE username = ?", (name,))
    conn.execute("DELETE FROM users WHERE username = ?", (name,))
    record_audit(conn, actor or name, "user_delete", name, {"role": str(row["role"])})
    return _public_user(row)


# --- Sessions --------------------------------------------------------------


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(
    conn: sqlite3.Connection,
    username: str,
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    *,
    actor: str | None = None,
) -> dict[str, Any]:
    """Start a session and return it, including the plaintext token once.

    This is the only function that ever returns the token. Only its hash is
    stored, so it cannot be recovered from the database afterwards. ``ttl_seconds``
    defaults to twelve hours.
    """

    row = _get_user(conn, username)
    if row is None:
        raise ValueError(f"Unknown user {username!r}.")
    name = str(row["username"])
    if not bool(row["enabled"]):
        raise ValueError(f"Cannot start a session for disabled user {name!r}.")

    try:
        ttl = int(ttl_seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError("ttl_seconds must be a whole number of seconds") from exc
    if ttl <= 0:
        raise ValueError("ttl_seconds must be greater than zero")

    token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    created = _utc_now()
    expires = (
        datetime.now(timezone.utc) + timedelta(seconds=ttl)
    ).isoformat(timespec="microseconds")
    conn.execute(
        "INSERT INTO sessions(token_hash, username, created_at, expires_at, revoked)"
        " VALUES (?,?,?,?,0)",
        (_token_hash(token), name, created, expires),
    )
    record_audit(
        conn, actor or name, "session_create", name,
        {"expires_at": expires, "ttl_seconds": ttl},
    )
    return {
        "token": token,
        "username": name,
        "created_at": created,
        "expires_at": expires,
        "ttl_seconds": ttl,
    }


def validate_session(
    conn: sqlite3.Connection,
    token: str,
) -> dict[str, Any] | None:
    """Return the session's user when ``token`` is live, otherwise ``None``.

    Honours expiry and revocation, and also requires that the user still exists
    and is enabled, so disabling an account ends its sessions immediately.
    """

    if not isinstance(token, str) or not token:
        return None

    row = conn.execute(
        "SELECT * FROM sessions WHERE token_hash = ?", (_token_hash(token),)
    ).fetchone()
    if row is None or bool(row["revoked"]):
        return None

    expires = _parse_iso(row["expires_at"])
    if expires is None or datetime.now(timezone.utc) >= expires:
        return None

    user = _get_user(conn, str(row["username"]))
    if user is None or not bool(user["enabled"]):
        return None

    return {
        "username": str(user["username"]),
        "role": str(user["role"]),
        "created_at": str(row["created_at"]),
        "expires_at": str(row["expires_at"]),
    }


def revoke_session(
    conn: sqlite3.Connection,
    token: str,
    *,
    actor: str | None = None,
) -> dict[str, Any]:
    """Revoke one session. Revoking an already-revoked session is a no-op."""

    if not isinstance(token, str) or not token:
        raise ValueError("A session token is required")
    row = conn.execute(
        "SELECT * FROM sessions WHERE token_hash = ?", (_token_hash(token),)
    ).fetchone()
    if row is None:
        raise ValueError("Unknown session token.")
    name = str(row["username"])
    if not bool(row["revoked"]):
        conn.execute(
            "UPDATE sessions SET revoked = 1 WHERE token_hash = ?", (_token_hash(token),)
        )
        record_audit(
            conn, actor or name, "session_revoke", name,
            {"expires_at": str(row["expires_at"])},
        )
    return {
        "username": name,
        "created_at": str(row["created_at"]),
        "expires_at": str(row["expires_at"]),
        "revoked": True,
    }


def revoke_user_sessions(
    conn: sqlite3.Connection,
    username: str,
    *,
    actor: str | None = None,
) -> int:
    """Revoke every live session a user has, returning how many were revoked."""

    row = _get_user(conn, username)
    if row is None:
        raise ValueError(f"Unknown user {username!r}.")
    name = str(row["username"])

    before = conn.total_changes
    conn.execute(
        "UPDATE sessions SET revoked = 1 WHERE username = ? AND revoked = 0", (name,)
    )
    revoked = conn.total_changes - before
    record_audit(conn, actor or name, "session_revoke_user", name, {"revoked": revoked})
    return revoked


def purge_expired_sessions(conn: sqlite3.Connection, *, actor: str = "system") -> int:
    """Delete sessions that have expired or been revoked; return the count.

    Revoked rows are removed as well as expired ones: once a session is dead it
    is only clutter, and the audit log already records that it existed.
    """

    before = conn.total_changes
    conn.execute(
        "DELETE FROM sessions WHERE revoked = 1 OR expires_at <= ?", (_utc_now(),)
    )
    purged = conn.total_changes - before
    record_audit(conn, actor, "session_purge", None, {"purged": purged})
    return purged


# --- Audit trail -----------------------------------------------------------


def _detail_text(detail: Any) -> str:
    if detail is None:
        return ""
    if isinstance(detail, str):
        return detail
    if isinstance(detail, (dict, list, tuple)):
        return json.dumps(detail, ensure_ascii=False, sort_keys=True, default=str)
    return str(detail)


def record_audit(
    conn: sqlite3.Connection,
    actor: str,
    action: str,
    target: str | None = None,
    detail: Any = None,
) -> dict[str, Any]:
    """Append one audit row and return it.

    ``actor`` and ``action`` are required and non-empty; ``detail`` may be a
    string or any JSON-serialisable value, which is stored as JSON text.
    """

    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("actor must be a non-empty string")
    if not isinstance(action, str) or not action.strip():
        raise ValueError("action must be a non-empty string")

    timestamp = _utc_now()
    target_text = "" if target is None else str(target)
    detail_text = _detail_text(detail)
    conn.execute(
        "INSERT INTO audit_log(timestamp, actor, action, target, detail)"
        " VALUES (?,?,?,?,?)",
        (timestamp, actor.strip(), action.strip(), target_text, detail_text),
    )
    return {
        "timestamp": timestamp,
        "actor": actor.strip(),
        "action": action.strip(),
        "target": target_text,
        "detail": detail_text,
    }


def list_audit(
    conn: sqlite3.Connection,
    limit: int = AUDIT_LIMIT_DEFAULT,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Audit rows, newest first, paged by ``limit`` and ``offset``."""

    try:
        limit_value = int(limit)
        offset_value = int(offset)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit and offset must be whole numbers") from exc
    limit_value = max(1, min(limit_value, AUDIT_LIMIT_MAX))
    offset_value = max(0, offset_value)

    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?",
        (limit_value, offset_value),
    ).fetchall()
    return [dict(row) for row in rows]


# --- Command line ----------------------------------------------------------


def _read_password(env_var: str = PASSWORD_ENV_VAR) -> str:
    """Read the bootstrap password from the environment or from stdin.

    Never from ``argv``: a password on the command line is visible in shell
    history and in the process table. On a terminal the prompt is hidden with
    ``getpass``; when piped, one line is read from stdin.
    """

    from_env = os.environ.get(env_var)
    if from_env:
        return from_env
    if sys.stdin is not None and sys.stdin.isatty():
        import getpass

        return getpass.getpass("Password: ")
    return sys.stdin.readline().rstrip("\r\n")


def main(argv: list[str] | None = None) -> int:
    """Create the first administrator. Returns a process exit code."""

    parser = argparse.ArgumentParser(
        prog="python -m src.auth",
        description="Account management for the local SIEM console.",
    )
    parser.add_argument(
        "--init-admin",
        metavar="USERNAME",
        required=True,
        help="Create this account with the admin role.",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("siem_live.db"),
        help="Path to the SQLite store. Default siem_live.db.",
    )
    parser.add_argument(
        "--role",
        choices=ROLES,
        default="admin",
        help="Role for the new account. Default admin.",
    )
    args = parser.parse_args(argv)

    password = _read_password()
    if not password:
        print(
            f"No password supplied. Set {PASSWORD_ENV_VAR} or pipe one on stdin.",
            file=sys.stderr,
        )
        return 1

    # This is the program entry point, so it owns its own connection and commit;
    # the library functions above deliberately do neither.
    conn = sqlite3.connect(args.db)
    try:
        ensure_schema(conn)
        user = create_user(conn, args.init_admin, password, args.role)
        conn.commit()
    except ValueError as exc:
        print(f"Could not create {args.init_admin!r}: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()

    print(
        f"Created {user['role']} {user['username']!r} in {args.db}. "
        "Set the password from the environment or stdin only."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
