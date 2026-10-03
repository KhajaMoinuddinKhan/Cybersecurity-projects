"""Login lockout and TOTP multi-factor authentication for the local SIEM console.

The README lists three things the console does not do: *no login rate limit, no
lockout and no multi-factor authentication; the only brake on guessing is the
scrypt cost*. This module supplies the last two. It records every login attempt,
locks an account out after a run of failures, and can require a time-based
one-time password (TOTP, RFC 6238) as a second factor after the password has
been checked.

What this module guarantees
---------------------------
* Every attempt is written to ``login_attempts`` with the username, the source
  address, an ISO-8601 UTC timestamp and an outcome of ``success`` or
  ``failure``. A lockout row is written to ``lockouts`` when the failure run
  reaches the threshold.
* A lockout is keyed on the *pair* of username and source address, not on the
  username alone and not globally. Five bad passwords for ``alice`` from one
  address do not lock ``alice`` out from another address, and they do not touch
  any other account. This is deliberate: it limits the damage an attacker can do
  from a single address without giving one address the power to deny service to
  a user who is logging in from somewhere else.
* A lockout expires on its own. ``is_locked_out`` compares the stored expiry
  with the current time and reports ``locked=False`` once it has passed; no
  administrator and no timer is needed. Nothing is deleted by a read, so the
  audit trail survives.
* A successful login clears the failure run *for that username and source
  address*: the failure rows and any lockout for that pair are removed, and the
  clearing is audited. Failures recorded from other addresses are untouched.
* TOTP follows RFC 6238 with HMAC-SHA1, a 30-second step and a drift window of
  plus or minus one step, so a code is accepted for the step before and the step
  after the current one as well as the current step. Only six-digit codes are
  accepted; anything else is rejected.
* Recovery codes are generated once at enrolment and shown to the caller exactly
  once. Only their SHA-256 hashes are stored, so a copy of the database does not
  contain a usable recovery code. Using one marks it used, and a used code is
  refused if it is presented again.
* Every function that changes stored state writes a row to ``auth``'s audit log
  through :func:`auth.record_audit`. Both successful and failed second-factor
  checks are recorded.

What this module does NOT do
----------------------------
* TOTP protects the login step only. It is a second factor for the password
  check; it does not protect a session token once issued, and it does not
  encrypt anything. A session created after a successful second-factor check is
  still a bearer token.
* The TOTP secret is stored in plaintext in the same SQLite file as everything
  else. Anyone who can read the database file can read the secret and generate
  valid codes, so MFA here protects against a stolen *password* (and against
  password guessing), not against an attacker who already has the database. It
  also does not protect against an attacker who can modify the database, who
  could simply disable the second factor.
* The lockout is per-username-and-address, not global. An attacker with a pool
  of addresses can still make ``max_failures`` guesses per address, and an
  attacker who knows a username can lock that user out from their own address
  (a nuisance denial of service, cleared with :func:`clear_lockout`).
* This module records and reports; it does not itself block a login. The HTTP
  layer must call :func:`is_locked_out` before checking a password and refuse
  when it says ``locked``. A route that forgets to ask is not protected.
* The source address is stored verbatim as text and is not validated as an IP
  address. It is whatever the caller passes, so behind a proxy it is only as
  trustworthy as the caller's handling of ``X-Forwarded-For``.
* MFA rows are keyed by username text; this module does not require that a
  ``users`` row with that name exists, and it does not check that the account is
  enabled. The caller is expected to have authenticated the user first.
* There is no TLS. This is a local application, and codes and secrets cross the
  network in cleartext if it is bound to anything other than localhost.

Parameters
----------
``max_failures`` (default 5), ``window_seconds`` (default 900) and
``lockout_seconds`` (default 900) are accepted by the functions that need them.
A failure run is the count of ``failure`` rows for one username-and-address pair
whose timestamp falls inside the window; when it reaches ``max_failures`` the
pair is locked for ``lockout_seconds``. The defaults are named constants
(:data:`DEFAULT_MAX_FAILURES`, :data:`DEFAULT_WINDOW_SECONDS`,
:data:`DEFAULT_LOCKOUT_SECONDS`) so a caller can use them explicitly.

Timestamps are ISO-8601 UTC strings with microseconds, the same form ``auth``
uses, so they compare correctly as text and parse back with
``datetime.fromisoformat``.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import sqlite3
import struct
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from . import auth

# --- Lockout defaults ------------------------------------------------------

DEFAULT_MAX_FAILURES = 5
DEFAULT_WINDOW_SECONDS = 900
DEFAULT_LOCKOUT_SECONDS = 900

# How many recent failure rows :func:`lockout_summary` reports.
DEFAULT_SUMMARY_LIMIT = 20

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"

# --- TOTP parameters -------------------------------------------------------

# RFC 6238 / RFC 4226 defaults: SHA-1, six digits, a thirty-second step.
TOTP_DIGITS = 6
TOTP_PERIOD = 30
TOTP_WINDOW = 1

# 160 bits, as the task specifies. Twenty bytes encode to thirty-two base32
# characters with no padding.
TOTP_SECRET_BYTES = 20

# --- Recovery codes --------------------------------------------------------

# Ten codes, each eight random bytes rendered as sixteen hex digits in four
# groups of four (64 bits of entropy per code).
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_BYTES = 8

_SCHEMA: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL COLLATE NOCASE,
        source_ip TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        outcome TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS lockouts (
        username TEXT NOT NULL COLLATE NOCASE,
        source_ip TEXT NOT NULL,
        locked_until TEXT NOT NULL,
        failure_count INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (username, source_ip)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS mfa (
        username TEXT NOT NULL COLLATE NOCASE PRIMARY KEY,
        secret TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        confirmed_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL COLLATE NOCASE,
        code_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        used_at TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_login_attempts_pair "
    "ON login_attempts(username, source_ip, outcome, timestamp)",
    "CREATE INDEX IF NOT EXISTS ix_login_attempts_timestamp "
    "ON login_attempts(timestamp)",
    "CREATE INDEX IF NOT EXISTS ix_lockouts_locked_until "
    "ON lockouts(locked_until)",
    "CREATE INDEX IF NOT EXISTS ix_mfa_recovery_username "
    "ON mfa_recovery_codes(username)",
)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create this module's tables if they are not already present.

    Idempotent, so a caller can run it on every startup. It also calls
    :func:`auth.ensure_schema` first, because the audit rows this module writes
    live in auth's ``audit_log`` table and this module must not assume the
    caller created it; that call also sets the connection's row factory to
    ``sqlite3.Row``, which the rest of the module relies on.
    """

    auth.ensure_schema(conn)
    for statement in _SCHEMA:
        conn.execute(statement)
    conn.commit()


# --- Time helpers ----------------------------------------------------------


def _utc_now() -> str:
    """An ISO-8601 UTC timestamp with microseconds, matching ``auth``."""

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


def _epoch_seconds(at_time: Any) -> float:
    """Normalise a TOTP reference time to POSIX seconds.

    ``None`` means now. A number is taken as seconds since the epoch; a
    ``datetime`` is converted, treating a naive value as UTC.
    """

    if at_time is None:
        return datetime.now(timezone.utc).timestamp()
    if isinstance(at_time, bool):
        raise ValueError("at_time must be a number of seconds or a datetime")
    if isinstance(at_time, (int, float)):
        return float(at_time)
    if isinstance(at_time, datetime):
        moment = at_time if at_time.tzinfo is not None else at_time.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    raise ValueError("at_time must be a number of seconds or a datetime")


# --- Input helpers ---------------------------------------------------------


def _require_text(value: Any, field: str) -> str:
    """Return ``value`` stripped, or raise ``ValueError`` if it is not text."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _require_positive_int(value: Any, field: str) -> int:
    """Return a positive integer, rejecting ``bool`` (a subclass of ``int``)."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _require_non_negative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


# --- TOTP (RFC 6238 / RFC 4226) --------------------------------------------


def generate_secret() -> str:
    """A fresh base32 TOTP secret: 160 bits, no padding.

    The result is thirty-two upper-case base32 characters, the form an
    authenticator app expects.
    """

    return base64.b32encode(secrets.token_bytes(TOTP_SECRET_BYTES)).decode("ascii").rstrip("=")


def _decode_secret(secret: Any) -> bytes:
    """Decode a base32 secret, raising ``ValueError`` when it is not valid.

    Padding is optional and the text is case-insensitive, so a secret copied
    from a URI with or without ``=`` works either way.
    """

    if not isinstance(secret, str) or not secret.strip():
        raise ValueError("secret must be a non-empty base32 string")
    text = secret.strip().replace(" ", "").upper()
    text += "=" * ((-len(text)) % 8)
    try:
        return base64.b32decode(text, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("secret is not valid base32") from exc


def _hotp(secret: bytes, counter: int, digits: int = TOTP_DIGITS) -> str:
    """The HOTP value (RFC 4226) for ``counter``, as a zero-padded string.

    This is the core the public :func:`verify_code` uses. ``digits`` is a
    parameter so the published RFC 6238 vectors, which are eight digits, can be
    checked against this same code path by the tests; the console itself always
    uses six.
    """

    if counter < 0:
        raise ValueError("counter must not be negative")
    message = struct.pack(">Q", counter)
    digest = hmac.new(secret, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return f"{binary % (10 ** digits):0{digits}d}"


def provisioning_uri(secret: str, username: str, issuer: str = "SIEM console") -> str:
    """An ``otpauth://`` URI an authenticator app can scan or import.

    The URI carries the SHA-1 algorithm, six digits and a thirty-second period,
    matching :func:`verify_code`. ``issuer`` labels the entry in the app.
    """

    secret_bytes = _decode_secret(secret)
    canonical = base64.b32encode(secret_bytes).decode("ascii").rstrip("=")
    name = _require_text(username, "username")
    issuer_text = _require_text(issuer, "issuer")
    label = quote(f"{issuer_text}:{name}", safe=":")
    return (
        f"otpauth://totp/{label}"
        f"?secret={canonical}"
        f"&issuer={quote(issuer_text, safe='')}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"
    )


def verify_code(
    secret: str,
    code: str,
    at_time: Any = None,
    window: int = TOTP_WINDOW,
) -> bool:
    """Whether ``code`` is a valid TOTP for ``secret`` at ``at_time``.

    ``at_time`` defaults to now; pass a POSIX timestamp or a ``datetime`` to
    check a code for a specific moment (the tests do). ``window`` is how many
    steps either side of the current one to accept: the default of 1 accepts
    the previous, current and next step, covering clock drift of up to thirty
    seconds in either direction. ``window=0`` accepts only the current step.

    Only a six-digit code is accepted. A code of the wrong shape, a wrong code,
    or an expired code returns ``False`` rather than raising, because a caller
    is checking user input. A malformed *secret* raises ``ValueError``: that is
    a configuration error, not user input.
    """

    secret_bytes = _decode_secret(secret)
    _require_non_negative_int(window, "window")
    if not isinstance(code, str):
        return False
    candidate = code.strip()
    if len(candidate) != TOTP_DIGITS or not candidate.isascii() or not candidate.isdigit():
        return False

    counter = int(_epoch_seconds(at_time) // TOTP_PERIOD)
    for offset in range(-window, window + 1):
        if counter + offset < 0:
            continue
        if hmac.compare_digest(_hotp(secret_bytes, counter + offset, TOTP_DIGITS), candidate):
            return True
    return False


# --- Lockout ---------------------------------------------------------------


def _count_failures(conn: sqlite3.Connection, username: str, source_ip: str, since: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM login_attempts"
        " WHERE username = ? AND source_ip = ? AND outcome = ? AND timestamp >= ?",
        (username, source_ip, OUTCOME_FAILURE, since),
    ).fetchone()
    return int(row[0])


def _window_start(now: datetime, window_seconds: int) -> str:
    return (now - timedelta(seconds=window_seconds)).isoformat(timespec="microseconds")


def record_failure(
    conn: sqlite3.Connection,
    username: str,
    source_ip: str,
    *,
    max_failures: int = DEFAULT_MAX_FAILURES,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    lockout_seconds: int = DEFAULT_LOCKOUT_SECONDS,
) -> dict[str, Any]:
    """Record a failed login and lock the pair out if the run reaches the limit.

    Returns a dict describing the attempt: the pair, the running failure count
    inside the window, whether this attempt triggered a lockout, and when that
    lockout ends. A lockout is created (or its expiry extended) when the count
    reaches ``max_failures``.
    """

    name = _require_text(username, "username")
    ip = _require_text(source_ip, "source_ip")
    _require_positive_int(max_failures, "max_failures")
    _require_positive_int(window_seconds, "window_seconds")
    _require_positive_int(lockout_seconds, "lockout_seconds")

    now = datetime.now(timezone.utc)
    stamp = now.isoformat(timespec="microseconds")
    conn.execute(
        "INSERT INTO login_attempts(username, source_ip, timestamp, outcome)"
        " VALUES (?,?,?,?)",
        (name, ip, stamp, OUTCOME_FAILURE),
    )
    count = _count_failures(conn, name, ip, _window_start(now, window_seconds))

    locked = False
    locked_until: str | None = None
    if count >= max_failures:
        locked_until = (now + timedelta(seconds=lockout_seconds)).isoformat(
            timespec="microseconds"
        )
        conn.execute(
            "INSERT OR REPLACE INTO lockouts"
            "(username, source_ip, locked_until, failure_count, created_at)"
            " VALUES (?,?,?,?,?)",
            (name, ip, locked_until, count, stamp),
        )
        locked = True
        auth.record_audit(
            conn, name, "lockout_triggered", name,
            {"source_ip": ip, "failure_count": count, "locked_until": locked_until},
        )

    auth.record_audit(
        conn, name, "login_failure", name,
        {"source_ip": ip, "failure_count": count, "locked": locked},
    )
    return {
        "username": name,
        "source_ip": ip,
        "outcome": OUTCOME_FAILURE,
        "failure_count": count,
        "max_failures": max_failures,
        "locked": locked,
        "locked_until": locked_until,
        "timestamp": stamp,
    }


def record_success(
    conn: sqlite3.Connection,
    username: str,
    source_ip: str,
) -> dict[str, Any]:
    """Record a successful login and clear that pair's failure run.

    The failure rows and any lockout for this username-and-source-address pair
    are deleted; failures recorded for the same username from a different
    address are left alone, because the lockout unit is the pair. Returns what
    was cleared.
    """

    name = _require_text(username, "username")
    ip = _require_text(source_ip, "source_ip")
    stamp = _utc_now()
    conn.execute(
        "INSERT INTO login_attempts(username, source_ip, timestamp, outcome)"
        " VALUES (?,?,?,?)",
        (name, ip, stamp, OUTCOME_SUCCESS),
    )

    before = conn.total_changes
    conn.execute(
        "DELETE FROM login_attempts"
        " WHERE username = ? AND source_ip = ? AND outcome = ?",
        (name, ip, OUTCOME_FAILURE),
    )
    cleared_failures = conn.total_changes - before

    before = conn.total_changes
    conn.execute(
        "DELETE FROM lockouts WHERE username = ? AND source_ip = ?", (name, ip)
    )
    cleared_lockout = (conn.total_changes - before) > 0

    auth.record_audit(
        conn, name, "login_success", name,
        {"source_ip": ip, "cleared_failures": cleared_failures, "cleared_lockout": cleared_lockout},
    )
    return {
        "username": name,
        "source_ip": ip,
        "outcome": OUTCOME_SUCCESS,
        "cleared_failures": cleared_failures,
        "cleared_lockout": cleared_lockout,
        "timestamp": stamp,
    }


def is_locked_out(
    conn: sqlite3.Connection,
    username: str,
    source_ip: str,
    *,
    max_failures: int = DEFAULT_MAX_FAILURES,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    lockout_seconds: int = DEFAULT_LOCKOUT_SECONDS,
) -> dict[str, Any]:
    """Whether this username-and-address pair is currently locked out.

    Read-only: it changes nothing and writes no audit row. It reports the
    current failure count inside the window, whether a lockout is active, and
    when an active lockout ends. A lockout whose expiry has passed reads as not
    locked, so it expires on its own without any administrator action. The
    ``max_failures``, ``window_seconds`` and ``lockout_seconds`` arguments only
    control what is reported and what the window is measured against; they do
    not alter stored state.
    """

    name = _require_text(username, "username")
    ip = _require_text(source_ip, "source_ip")
    _require_positive_int(max_failures, "max_failures")
    _require_positive_int(window_seconds, "window_seconds")
    _require_positive_int(lockout_seconds, "lockout_seconds")

    now = datetime.now(timezone.utc)
    count = _count_failures(conn, name, ip, _window_start(now, window_seconds))

    locked = False
    locked_until: str | None = None
    remaining: int | None = None
    row = conn.execute(
        "SELECT locked_until FROM lockouts WHERE username = ? AND source_ip = ?",
        (name, ip),
    ).fetchone()
    if row is not None:
        until = _parse_iso(row["locked_until"])
        if until is not None and until > now:
            locked = True
            locked_until = str(row["locked_until"])
            remaining = max(0, int((until - now).total_seconds()))

    return {
        "locked": locked,
        "username": name,
        "source_ip": ip,
        "failure_count": count,
        "max_failures": max_failures,
        "window_seconds": window_seconds,
        "lockout_seconds": lockout_seconds,
        "locked_until": locked_until,
        "remaining_seconds": remaining,
    }


def clear_lockout(
    conn: sqlite3.Connection,
    username: str | None = None,
    source_ip: str | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """An administrator clears lockouts, by username, by address, or both.

    At least one of ``username`` and ``source_ip`` must be given; passing
    neither would delete every lockout and is refused. Only lockout rows are
    removed: the ``login_attempts`` history is left in place as evidence, and
    the action is written to the audit log with ``actor`` as who did it. The
    number of lockouts removed is returned, and the audit row is written even
    when the count is zero, so an attempt to clear is still visible.
    """

    if username is None and source_ip is None:
        raise ValueError("clear_lockout requires a username, a source_ip, or both")

    clauses: list[str] = []
    params: list[str] = []
    if username is not None:
        clauses.append("username = ?")
        params.append(_require_text(username, "username"))
    if source_ip is not None:
        clauses.append("source_ip = ?")
        params.append(_require_text(source_ip, "source_ip"))

    before = conn.total_changes
    conn.execute(f"DELETE FROM lockouts WHERE {' AND '.join(clauses)}", tuple(params))
    cleared = conn.total_changes - before

    who = actor.strip() if isinstance(actor, str) and actor.strip() else "system"
    auth.record_audit(
        conn, who, "lockout_clear", username,
        {"username": username, "source_ip": source_ip, "cleared": cleared},
    )
    return {
        "username": username,
        "source_ip": source_ip,
        "cleared": cleared,
        "actor": who,
    }


def lockout_summary(
    conn: sqlite3.Connection,
    *,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    limit: int = DEFAULT_SUMMARY_LIMIT,
) -> dict[str, Any]:
    """The lockouts in force now and the recent failure counts.

    ``active_lockouts`` lists the pairs whose lockout has not yet expired,
    soonest to expire first. ``recent_failures`` lists the pairs with failures
    inside ``window_seconds``, busiest first, capped at ``limit``.
    """

    _require_positive_int(window_seconds, "window_seconds")
    _require_positive_int(limit, "limit")

    now = datetime.now(timezone.utc)
    stamp = now.isoformat(timespec="microseconds")

    active: list[dict[str, Any]] = []
    rows = conn.execute(
        "SELECT username, source_ip, locked_until, failure_count FROM lockouts"
        " WHERE locked_until > ? ORDER BY locked_until ASC",
        (stamp,),
    ).fetchall()
    for row in rows:
        until = _parse_iso(row["locked_until"])
        remaining = max(0, int((until - now).total_seconds())) if until else 0
        active.append(
            {
                "username": str(row["username"]),
                "source_ip": str(row["source_ip"]),
                "locked_until": str(row["locked_until"]),
                "failure_count": int(row["failure_count"]),
                "remaining_seconds": remaining,
            }
        )

    since = _window_start(now, window_seconds)
    recent: list[dict[str, Any]] = []
    frows = conn.execute(
        "SELECT username, source_ip, COUNT(*) AS n FROM login_attempts"
        " WHERE outcome = ? AND timestamp >= ?"
        " GROUP BY username, source_ip ORDER BY n DESC, username ASC, source_ip ASC"
        " LIMIT ?",
        (OUTCOME_FAILURE, since, limit),
    ).fetchall()
    for row in frows:
        recent.append(
            {
                "username": str(row["username"]),
                "source_ip": str(row["source_ip"]),
                "failure_count": int(row["n"]),
            }
        )

    total = conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE outcome = ? AND timestamp >= ?",
        (OUTCOME_FAILURE, since),
    ).fetchone()[0]

    return {
        "generated_at": stamp,
        "window_seconds": window_seconds,
        "active_lockouts": active,
        "recent_failures": recent,
        "recent_failure_total": int(total),
    }


# --- Multi-factor authentication -------------------------------------------


def _normalise_recovery_code(code: Any) -> str:
    """Upper-case and strip everything that is not a letter or digit.

    So ``abcd-ef01`` and ``ABCDEF01`` are the same code, and a user may type a
    recovery code with or without the grouping dashes.
    """

    return "".join(ch for ch in str(code).upper() if ch.isalnum())


def _hash_recovery_code(code: Any) -> str:
    return hashlib.sha256(_normalise_recovery_code(code).encode("utf-8")).hexdigest()


def _recovery_codes_remaining(conn: sqlite3.Connection, username: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM mfa_recovery_codes WHERE username = ? AND used_at IS NULL",
        (username,),
    ).fetchone()
    return int(row[0])


def mfa_status(conn: sqlite3.Connection, username: str) -> dict[str, Any]:
    """Whether MFA is set up for a user, without revealing the secret.

    ``enrolled`` means a secret row exists; ``enabled`` means it has been
    confirmed with a working code and the second factor is in force; ``pending``
    means a secret exists but has not been confirmed. The secret itself is never
    returned by this function.
    """

    name = _require_text(username, "username")
    row = conn.execute(
        "SELECT enabled, created_at, confirmed_at FROM mfa WHERE username = ?",
        (name,),
    ).fetchone()
    remaining = _recovery_codes_remaining(conn, name)
    if row is None:
        return {
            "username": name,
            "enrolled": False,
            "enabled": False,
            "pending": False,
            "created_at": "",
            "confirmed_at": "",
            "recovery_codes_remaining": remaining,
        }
    enabled = bool(row["enabled"])
    return {
        "username": name,
        "enrolled": True,
        "enabled": enabled,
        "pending": not enabled,
        "created_at": str(row["created_at"]),
        "confirmed_at": row["confirmed_at"] or "",
        "recovery_codes_remaining": remaining,
    }


def start_enrolment(conn: sqlite3.Connection, username: str) -> dict[str, Any]:
    """Begin MFA enrolment and return the secret, URI and recovery codes.

    This is the only moment the recovery codes exist in plaintext: only their
    hashes are stored, so they cannot be shown again. Enrolment leaves MFA
    disabled until :func:`confirm_enrolment` verifies a code, and starting again
    replaces any previous secret and recovery codes.
    """

    name = _require_text(username, "username")
    secret = generate_secret()
    uri = provisioning_uri(secret, name)
    now = _utc_now()

    conn.execute(
        "INSERT OR REPLACE INTO mfa(username, secret, enabled, created_at, confirmed_at)"
        " VALUES (?,?,0,?,NULL)",
        (name, secret, now),
    )
    conn.execute("DELETE FROM mfa_recovery_codes WHERE username = ?", (name,))

    codes: list[str] = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = secrets.token_hex(RECOVERY_CODE_BYTES).upper()
        display = "-".join(raw[i : i + 4] for i in range(0, len(raw), 4))
        codes.append(display)
        conn.execute(
            "INSERT INTO mfa_recovery_codes(username, code_hash, created_at, used_at)"
            " VALUES (?,?,?,NULL)",
            (name, _hash_recovery_code(display), now),
        )

    auth.record_audit(conn, name, "mfa_enrol_start", name, {"recovery_codes": len(codes)})
    return {
        "username": name,
        "secret": secret,
        "provisioning_uri": uri,
        "recovery_codes": codes,
        "created_at": now,
    }


def confirm_enrolment(
    conn: sqlite3.Connection,
    username: str,
    code: str,
) -> dict[str, Any]:
    """Finish MFA enrolment, but only if ``code`` verifies against the secret.

    A code that does not match raises ``ValueError`` and changes nothing, so a
    mistyped confirmation cannot enable a secret the user has not actually
    loaded into their authenticator. On success MFA is enabled and the change is
    audited. Returns the new :func:`mfa_status`.
    """

    name = _require_text(username, "username")
    row = conn.execute(
        "SELECT secret FROM mfa WHERE username = ?", (name,)
    ).fetchone()
    if row is None:
        raise ValueError(f"No MFA enrolment to confirm for {name!r}.")
    if not verify_code(str(row["secret"]), code):
        raise ValueError("The code did not match the enrolment secret.")

    conn.execute(
        "UPDATE mfa SET enabled = 1, confirmed_at = ? WHERE username = ?",
        (_utc_now(), name),
    )
    auth.record_audit(conn, name, "mfa_enrol_confirm", name)
    return mfa_status(conn, name)


def disable_mfa(
    conn: sqlite3.Connection,
    username: str,
    actor: str | None = None,
) -> dict[str, Any]:
    """Turn MFA off for a user and delete the recovery codes.

    Removing the secret and the codes together means a later re-enrolment cannot
    inherit the old codes. When nothing was enrolled this is a no-op that
    reports ``disabled=False`` and writes no audit row, because nothing changed.
    """

    name = _require_text(username, "username")
    existing = conn.execute("SELECT 1 FROM mfa WHERE username = ?", (name,)).fetchone()

    conn.execute("DELETE FROM mfa WHERE username = ?", (name,))
    before = conn.total_changes
    conn.execute("DELETE FROM mfa_recovery_codes WHERE username = ?", (name,))
    removed = conn.total_changes - before

    who = actor.strip() if isinstance(actor, str) and actor.strip() else name
    if existing is None:
        return {
            "username": name,
            "disabled": False,
            "recovery_codes_removed": 0,
            "actor": who,
        }

    auth.record_audit(conn, who, "mfa_disable", name, {"recovery_codes_removed": removed})
    return {
        "username": name,
        "disabled": True,
        "recovery_codes_removed": removed,
        "actor": who,
    }


def verify_login_code(conn: sqlite3.Connection, username: str, code: str) -> dict[str, Any]:
    """Check a second-factor code: a TOTP code or an unused recovery code.

    A valid TOTP code is accepted as method ``totp``. If it is not a valid TOTP
    code, an unused recovery code with the same value is accepted as method
    ``recovery_code`` and marked used, so it is refused the second time. A
    failure returns ``valid=False`` with a short reason rather than raising,
    because the code is user input. When MFA is not enabled for the user this
    returns ``valid=False``; the caller should only ask when it is enabled.

    Both successes and failures are written to the audit log.
    """

    name = _require_text(username, "username")
    row = conn.execute(
        "SELECT secret, enabled FROM mfa WHERE username = ?", (name,)
    ).fetchone()
    remaining = _recovery_codes_remaining(conn, name)

    if row is None or not bool(row["enabled"]):
        return {
            "username": name,
            "valid": False,
            "method": None,
            "enabled": False,
            "recovery_codes_remaining": remaining,
            "reason": "multi-factor authentication is not enabled",
        }

    if isinstance(code, str) and code.strip() and verify_code(str(row["secret"]), code):
        auth.record_audit(conn, name, "mfa_login", name, {"method": "totp"})
        return {
            "username": name,
            "valid": True,
            "method": "totp",
            "enabled": True,
            "recovery_codes_remaining": remaining,
            "reason": "",
        }

    if isinstance(code, str) and code.strip():
        digest = _hash_recovery_code(code)
        match = conn.execute(
            "SELECT id FROM mfa_recovery_codes"
            " WHERE username = ? AND code_hash = ? AND used_at IS NULL",
            (name, digest),
        ).fetchone()
        if match is not None:
            conn.execute(
                "UPDATE mfa_recovery_codes SET used_at = ? WHERE id = ?",
                (_utc_now(), match["id"]),
            )
            auth.record_audit(
                conn, name, "mfa_recovery_used", name,
                {"remaining": remaining - 1},
            )
            return {
                "username": name,
                "valid": True,
                "method": "recovery_code",
                "enabled": True,
                "recovery_codes_remaining": remaining - 1,
                "reason": "",
            }

    auth.record_audit(conn, name, "mfa_login_failed", name)
    return {
        "username": name,
        "valid": False,
        "method": None,
        "enabled": True,
        "recovery_codes_remaining": remaining,
        "reason": "the code did not match",
    }
