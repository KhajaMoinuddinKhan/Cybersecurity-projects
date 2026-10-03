"""Host registry: enrol agents, authenticate them, and see which are alive.

The collector in ``windows_collector.py`` reads the machine it runs on, which
makes the console a single-host tool: the README calls that out as the feature a
real SIEM has and this one does not. This module is the missing half of the
answer. It keeps a registry of the hosts an operator has enrolled, hands each
one a key at enrolment, and can answer the two questions that matter once there
is more than one source: *which hosts are reporting* and *is this host who it
says it is*.

What it deliberately does not do is carry events. There is no agent process and
no forwarding protocol here; an enrolled host still ships events through
``POST /api/events`` or an import. What this module adds is identity, enrolment
and liveness, so those events can be attributed to a registered host instead of
arriving anonymously.

Enrolment keys
--------------
A key is generated as ``"hk_"`` followed by 43 characters of URL-safe base64
(``secrets.token_urlsafe(32)``), which is 256 bits of randomness. The plaintext
key is returned by :func:`enrol_host` and :func:`rotate_host_key` and is the
only moment it exists outside the agent: only a salted hash is ever stored, so
the key cannot be recovered from the database and a lost key is replaced by
rotation, not by lookup.

The stored form is a per-host random 16-byte salt plus
PBKDF2-HMAC-SHA256(key, salt, 100000 iterations), both kept as hex. The key is
high-entropy, so it is not guessable and the key-stretching is defence in depth:
a stolen database does not yield a usable key, and two hosts that somehow chose
the same key would still hold different hashes. Verification recomputes the hash
and compares with :func:`hmac.compare_digest`, so a wrong key cannot be told
apart by timing.

Liveness
--------
Each host carries ``first_seen``, ``last_seen`` and an ``event_count``. A host's
``status`` is computed when it is read, not stored:

``online``          reported at least one event and was last seen inside the
                    stale window.
``stale``           reported before, but not since the window closed.
``never-reported``  enrolled, but no event has ever been attributed to it.

This is a self-reported liveness signal. A host that is switched off without
telling anyone stays ``online`` until the stale window passes, and there is no
heartbeat beyond the caller invoking :func:`touch_host`.

Timestamps are UTC and are stored in the same space-separated form the event
store uses (``YYYY-MM-DD HH:MM:SS``), so a host's ``last_seen`` can be compared
against ``live_events.timestamp`` directly. Columns are read by position, so the
connection may use any row factory; ``app.get_connection``'s ``sqlite3.Row`` is
what the console uses.

Removal
-------
:func:`remove_host` refuses to delete a host that still has events, either
recorded in the registry's own ``event_count`` or present in the ``live_events``
table under that host's name, because dropping the registry entry first would
leave those events unattributed with nothing pointing at them. The refusal is
lifted with ``force=True``, which removes only the registry entry: the events
themselves are left in place, deliberately, because this module does not own
them. Events are matched to a host by exact ``host`` name text, since
``live_events`` has no ``host_id`` column and its existing columns must not be
changed.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any

KEY_PREFIX = "hk_"

# Length of the per-host salt, in bytes.
KEY_SALT_BYTES = 16

# PBKDF2 work factor. The key is 256 bits of randomness, so this is defence in
# depth rather than the thing that makes the key unguessable.
KEY_ITERATIONS = 100_000

KEY_HASH_ALGORITHM = "sha256"

# How long a host may go without reporting before it reads as stale.
DEFAULT_STALE_SECONDS = 300

ONLINE = "online"
STALE = "stale"
NEVER_REPORTED = "never-reported"

# The order the summary reports them in.
STATUSES = (ONLINE, STALE, NEVER_REPORTED)

SCHEMA = """CREATE TABLE IF NOT EXISTS hosts (
host_id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT NOT NULL UNIQUE,
platform TEXT NOT NULL DEFAULT '',
agent_version TEXT NOT NULL DEFAULT '',
first_seen TEXT NOT NULL,
last_seen TEXT NOT NULL,
event_count INTEGER NOT NULL DEFAULT 0,
enabled INTEGER NOT NULL DEFAULT 1,
key_salt TEXT NOT NULL,
key_hash TEXT NOT NULL,
key_created_at TEXT NOT NULL
)"""

INDEXES = (
    "CREATE INDEX IF NOT EXISTS ix_hosts_last_seen ON hosts(last_seen)",
)

# Named columns rather than SELECT *, so a row can be read by position and the
# module works whether or not the connection sets a Row factory.
_SELECT = (
    "SELECT host_id,name,platform,agent_version,first_seen,last_seen,"
    "event_count,enabled,key_salt,key_hash,key_created_at FROM hosts"
)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the host registry if it is not already there.

    Idempotent: safe to call on every request, and it never touches an existing
    row. Callers invoke this once before using the rest of the module.
    """

    conn.execute(SCHEMA)
    for statement in INDEXES:
        conn.execute(statement)
    conn.commit()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse_utc(value: Any) -> datetime | None:
    """Read a stored timestamp as an aware UTC datetime, or None if unreadable."""

    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _require_positive_int(value: Any, field: str) -> int:
    # bool is a subclass of int; True is not a valid id.
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _require_seconds(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("stale_after_seconds must be a non-negative integer")
    return value


def _new_key() -> tuple[str, str, str]:
    """Return a fresh (plaintext key, salt hex, hash hex) triple."""

    key = KEY_PREFIX + secrets.token_urlsafe(32)
    salt = secrets.token_bytes(KEY_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        KEY_HASH_ALGORITHM, key.encode("utf-8"), salt, KEY_ITERATIONS
    )
    return key, salt.hex(), digest.hex()


def _hash_key(key: str, salt_hex: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        KEY_HASH_ALGORITHM, key.encode("utf-8"), bytes.fromhex(salt_hex), KEY_ITERATIONS
    )


def _fetch(conn: sqlite3.Connection, host_id: int) -> Any:
    row = conn.execute(_SELECT + " WHERE host_id = ?", (host_id,)).fetchone()
    if row is None:
        raise ValueError(f"No host with id {host_id}")
    return row


def _status_and_age(row: Any, now: datetime, stale_after_seconds: int) -> tuple[str, int | None]:
    last_seen = _parse_utc(row[5])
    if last_seen is None:
        age: int | None = None
    else:
        age = int((now - last_seen).total_seconds())
        if age < 0:  # a clock that runs backwards must not read as a negative age
            age = 0

    count = int(row[6])
    if count == 0:
        status = NEVER_REPORTED
    elif age is None or age > stale_after_seconds:
        status = STALE
    else:
        status = ONLINE
    return status, age


def _record(row: Any, now: datetime, stale_after_seconds: int) -> dict[str, Any]:
    status, age = _status_and_age(row, now, stale_after_seconds)
    return {
        "host_id": int(row[0]),
        "name": str(row[1]),
        "platform": str(row[2]),
        "agent_version": str(row[3]),
        "first_seen": str(row[4]),
        "last_seen": str(row[5]),
        "event_count": int(row[6]),
        "enabled": bool(row[7]),
        "key_created_at": str(row[10]),
        "status": status,
        "age_seconds": age,
    }


def _one(conn: sqlite3.Connection, host_id: int, stale_after_seconds: int = DEFAULT_STALE_SECONDS) -> dict[str, Any]:
    return _record(_fetch(conn, host_id), datetime.now(timezone.utc), stale_after_seconds)


def enrol_host(
    conn: sqlite3.Connection,
    name: str,
    platform: str | None = None,
    agent_version: str | None = None,
) -> dict[str, Any]:
    """Register a host and hand it a key.

    Returns the new host's record with a ``key`` field holding the plaintext
    enrolment key. This is the only moment the plaintext key exists outside the
    agent: only its salted hash is stored, so the key cannot be read back later.
    If it is lost, call :func:`rotate_host_key`, which issues a fresh one.

    ``name`` must be a non-empty string and must be unique; a duplicate raises
    ``ValueError``. ``platform`` and ``agent_version`` are optional and default
    to empty strings.
    """

    clean = _require_text(name, "name")
    key, salt_hex, hash_hex = _new_key()
    stamp = _now()
    try:
        cursor = conn.execute(
            "INSERT INTO hosts("
            "name,platform,agent_version,first_seen,last_seen,event_count,enabled,"
            "key_salt,key_hash,key_created_at) VALUES (?,?,?,?,?,0,1,?,?,?)",
            (
                clean,
                "" if platform is None else str(platform).strip(),
                "" if agent_version is None else str(agent_version).strip(),
                stamp,
                stamp,
                salt_hex,
                hash_hex,
                stamp,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"A host named {clean!r} is already enrolled") from exc
    conn.commit()

    record = _one(conn, int(cursor.lastrowid))
    record["key"] = key
    return record


def verify_host_key(conn: sqlite3.Connection, host_id: int, key: str) -> bool:
    """Return whether ``key`` is the enrolment key for ``host_id``.

    The comparison is constant-time (:func:`hmac.compare_digest`) against the
    stored PBKDF2 hash. An unknown host returns ``False`` rather than raising,
    so a caller checking a key cannot tell "no such host" apart from "wrong
    key"; a structurally invalid call (a non-integer id, an empty key) still
    raises ``ValueError``.
    """

    _require_positive_int(host_id, "host_id")
    if not isinstance(key, str) or not key:
        raise ValueError("key must be a non-empty string")

    row = conn.execute(
        "SELECT key_salt, key_hash FROM hosts WHERE host_id = ?", (host_id,)
    ).fetchone()
    if row is None:
        return False
    try:
        stored = bytes.fromhex(str(row[1]))
    except ValueError:
        # A corrupted hash cannot match anything; treat it as a failed check
        # rather than crashing the caller.
        return False
    return hmac.compare_digest(_hash_key(key, str(row[0])), stored)


def touch_host(conn: sqlite3.Connection, host_id: int, event_count: int = 0) -> dict[str, Any]:
    """Mark a host as just seen and add to its event counter.

    ``last_seen`` is set to now and ``event_count`` is incremented by
    ``event_count`` in a single statement, so concurrent callers cannot lose an
    increment to a read-then-write race. Returns the updated record. An unknown
    host raises ``ValueError``. Whether a disabled host should be allowed to
    report is the caller's decision, so ``enabled`` is not checked here.
    """

    _require_positive_int(host_id, "host_id")
    if isinstance(event_count, bool) or not isinstance(event_count, int) or event_count < 0:
        raise ValueError("event_count must be a non-negative integer")

    cursor = conn.execute(
        "UPDATE hosts SET last_seen = ?, event_count = event_count + ? WHERE host_id = ?",
        (_now(), event_count, host_id),
    )
    if cursor.rowcount == 0:
        raise ValueError(f"No host with id {host_id}")
    conn.commit()
    return _one(conn, host_id)


def list_hosts(
    conn: sqlite3.Connection, stale_after_seconds: int = DEFAULT_STALE_SECONDS
) -> list[dict[str, Any]]:
    """Every registered host with a computed ``status`` and ``age_seconds``.

    ``age_seconds`` is how long ago the host was last seen; it is ``None`` only
    if the stored timestamp cannot be parsed. ``status`` is one of ``online``,
    ``stale`` or ``never-reported`` (see the module docstring). A negative age
    from a clock that ran backwards is reported as ``0``.
    """

    _require_seconds(stale_after_seconds)
    now = datetime.now(timezone.utc)
    rows = conn.execute(_SELECT + " ORDER BY name COLLATE NOCASE, host_id").fetchall()
    return [_record(row, now, stale_after_seconds) for row in rows]


def host_summary(
    conn: sqlite3.Connection, stale_after_seconds: int = DEFAULT_STALE_SECONDS
) -> dict[str, int]:
    """Count the registry by status, plus the total.

    Keys are ``online``, ``stale``, ``never-reported`` and ``total``.
    """

    counts = {status: 0 for status in STATUSES}
    for host in list_hosts(conn, stale_after_seconds):
        counts[host["status"]] += 1
    counts["total"] = sum(counts[status] for status in STATUSES)
    return counts


def get_host(conn: sqlite3.Connection, host_id: int) -> dict[str, Any]:
    """One host's record, without its key. Unknown id raises ``ValueError``."""

    _require_positive_int(host_id, "host_id")
    return _one(conn, host_id)


def disable_host(conn: sqlite3.Connection, host_id: int) -> dict[str, Any]:
    """Stop accepting a host's reports. Idempotent; unknown id raises."""

    return _set_enabled(conn, host_id, False)


def enable_host(conn: sqlite3.Connection, host_id: int) -> dict[str, Any]:
    """Re-enable a host. Idempotent; unknown id raises."""

    return _set_enabled(conn, host_id, True)


def _set_enabled(conn: sqlite3.Connection, host_id: int, enabled: bool) -> dict[str, Any]:
    _require_positive_int(host_id, "host_id")
    cursor = conn.execute(
        "UPDATE hosts SET enabled = ? WHERE host_id = ?",
        (1 if enabled else 0, host_id),
    )
    if cursor.rowcount == 0:
        raise ValueError(f"No host with id {host_id}")
    conn.commit()
    return _one(conn, host_id)


def rotate_host_key(conn: sqlite3.Connection, host_id: int) -> dict[str, Any]:
    """Issue a fresh key for a host, invalidating the old one.

    Returns the host's record with the new plaintext ``key``, which is available
    only here. Unknown id raises ``ValueError``.
    """

    _require_positive_int(host_id, "host_id")
    _fetch(conn, host_id)
    key, salt_hex, hash_hex = _new_key()
    conn.execute(
        "UPDATE hosts SET key_salt = ?, key_hash = ?, key_created_at = ? WHERE host_id = ?",
        (salt_hex, hash_hex, _now(), host_id),
    )
    conn.commit()
    record = _one(conn, host_id)
    record["key"] = key
    return record


def _event_rows(conn: sqlite3.Connection, name: str) -> int:
    """Stored events attributed to a host name, if the event table exists."""

    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'live_events'"
    ).fetchone()
    if exists is None:
        return 0
    row = conn.execute(
        "SELECT COUNT(*) FROM live_events WHERE host = ?", (name,)
    ).fetchone()
    return int(row[0])


def remove_host(conn: sqlite3.Connection, host_id: int, *, force: bool = False) -> None:
    """Delete a host's registry entry.

    Refuses with ``ValueError`` if the host still has events, either counted in
    its ``event_count`` or present in ``live_events`` under its name, so an
    operator cannot silently orphan stored data. ``force=True`` overrides the
    refusal and removes the registry entry only: the events are left where they
    are, unattributed, because this module does not own them. Unknown id raises
    ``ValueError``.
    """

    _require_positive_int(host_id, "host_id")
    row = _fetch(conn, host_id)
    name = str(row[1])
    reported = int(row[6])

    if not force:
        if reported > 0:
            raise ValueError(
                f"Host {name!r} has reported {reported} event(s). Remove its events "
                "first, or pass force=True to drop the registry entry anyway."
            )
        stored = _event_rows(conn, name)
        if stored > 0:
            raise ValueError(
                f"Host {name!r} still has {stored} event(s) in the live store. Remove "
                "those events first, or pass force=True to drop the registry entry anyway."
            )

    conn.execute("DELETE FROM hosts WHERE host_id = ?", (host_id,))
    conn.commit()
