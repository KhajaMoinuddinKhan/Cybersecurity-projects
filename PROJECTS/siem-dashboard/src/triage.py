"""Analyst triage: turn stored detections into assignable, tunable work.

A detection is a row in ``live_events`` with ``is_alert = 1``. This module adds
the analyst workflow on top of those rows: a status, an owner, an investigation
record and a way to tune a noisy rule out of the queue. It owns its own tables
and never opens a database of its own -- every function takes a live
``sqlite3.Connection`` and the caller invokes :func:`ensure_schema` once.

What is stored
--------------
``detection_state``
    One row per detection, keyed by (host_id, rule_id, event_id), holding the
    status, the assignee and who last touched it. ``event_id`` here is the
    ``id`` of the stored ``live_events`` row -- the detection's own identity --
    not the Windows/Sysmon ``event_id`` field.
``detection_transitions``
    Append-only. Every :func:`set_status` call records the status it came from,
    the status it moved to, who did it and when, so the path through a
    detection stays visible after the fact.
``detection_notes``
    Append-only investigation record. There is no update or delete: a note is
    the record of what an analyst thought, and overwriting it would destroy
    exactly the evidence this module exists to keep.
``suppressions``
    The tuning loop. A host-scoped suppression silences one rule for one host; a
    global one silences it for every host. Expiry is evaluated when the
    suppression is read, so an expired rule stops applying on its own, with no
    cleanup job.

Honest limits
-------------
Suppression is a workflow convenience, not a guarantee about detection quality.
A suppressed rule still fires, still classifies the event, and the event is
still stored with its rule id: it is only hidden from the triage queue built by
:func:`list_detections`. Nothing here changes what the rule engine decides, and
suppressing a true positive hides it just as effectively as a false one.

Marking a detection ``false_positive`` records a judgement; it does not create a
suppression. The offer to suppress is built by :func:`suggest_suppression` (and
returned by :func:`set_status` as ``suppression_offer``) and is applied only by
an explicit :func:`suppress` call, so the analyst decides.

Assigning an owner does not append a transition: the transition table records
status changes only. ``set_status`` appends a transition on every call, so a
repeated status shows up as a repeat in the history.

Every write commits on the connection it is given.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

# The states a detection can be in. "new" is the state of a detection nobody has
# touched, so it is the implicit status when no state row exists yet.
DETECTION_STATUSES = ("new", "acknowledged", "investigating", "closed", "false_positive")

SUPPRESSION_SCOPES = ("host", "global")

# The queue is ordered by severity first (High, Medium, Low, then anything
# unexpected), because the point of a triage queue is what to look at first.
_SEVERITY_ORDER = (
    "CASE e.severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 WHEN 'Low' THEN 2 ELSE 3 END"
)

SCHEMA = (
    """
CREATE TABLE IF NOT EXISTS detection_state (
    host_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('new','acknowledged','investigating','closed','false_positive')),
    assignee TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    PRIMARY KEY (host_id, rule_id, event_id)
)
""",
    """
CREATE TABLE IF NOT EXISTS detection_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    assignee TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL,
    changed_at TEXT NOT NULL
)
""",
    """
CREATE TABLE IF NOT EXISTS detection_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
)
""",
    """
CREATE TABLE IF NOT EXISTS suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    host_id TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL CHECK (scope IN ('host','global')),
    reason TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL DEFAULT '',
    revoked_at TEXT NOT NULL DEFAULT '',
    revoked_by TEXT NOT NULL DEFAULT ''
)
""",
    "CREATE INDEX IF NOT EXISTS ix_detection_state_host ON detection_state(host_id)",
    "CREATE INDEX IF NOT EXISTS ix_detection_notes_detection ON detection_notes(host_id, rule_id, event_id)",
    "CREATE INDEX IF NOT EXISTS ix_detection_transitions_detection ON detection_transitions(host_id, rule_id, event_id)",
    "CREATE INDEX IF NOT EXISTS ix_suppressions_rule ON suppressions(rule_id, host_id)",
)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create this module's tables and indexes if they are not already there.

    Idempotent: callers may invoke it on every request. It also points the
    connection at ``sqlite3.Row`` when nothing else has, so every read below can
    address columns by name.
    """

    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row
    for statement in SCHEMA:
        conn.execute(statement)
    conn.commit()


def _now() -> str:
    """The current time as an ISO-8601 UTC string."""

    return datetime.now(timezone.utc).isoformat()


def _text(value: Any, field: str) -> str:
    """A required, non-empty string field, or a ValueError naming it."""

    text = "" if value is None else str(value).strip()
    if not text:
        raise ValueError(f"{field} is required")
    return text


def _identity(detection: dict[str, Any]) -> tuple[str, str, str]:
    """The (host_id, rule_id, event_id) a detection is keyed by.

    ``event_id`` is the stored event row's ``id`` when it is present, falling
    back to a supplied ``event_id``. An empty ``rule_id`` is a valid stored
    value and is accepted; a missing one is not.
    """

    if not isinstance(detection, dict):
        raise ValueError("detection must be a mapping with host, rule_id and id")
    host = detection.get("host") or detection.get("host_id")
    rule = detection.get("rule_id")
    event = detection.get("id")
    if event is None:
        event = detection.get("event_id")
    if host is None or not str(host).strip():
        raise ValueError("detection needs a host (or host_id)")
    if rule is None:
        raise ValueError("detection needs a rule_id")
    if event is None or not str(event).strip():
        raise ValueError("detection needs an event id (id)")
    return str(host).strip(), str(rule).strip(), str(event).strip()


def _fetchall(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row
    return conn.execute(sql, params).fetchall()


def _fetchone(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row
    return conn.execute(sql, params).fetchone()


def _state_row(conn: sqlite3.Connection, host: str, rule: str, event: str) -> dict[str, Any] | None:
    row = _fetchone(
        conn,
        "SELECT host_id, rule_id, event_id, status, assignee, updated_at, updated_by "
        "FROM detection_state WHERE host_id = ? AND rule_id = ? AND event_id = ?",
        (host, rule, event),
    )
    return dict(row) if row is not None else None


def _normalise_status(value: Any) -> str:
    """Return a supported detection status, or raise ValueError."""

    candidate = str(value or "").strip().lower()
    if candidate not in DETECTION_STATUSES:
        raise ValueError(
            f"Unsupported status {value!r}. Expected one of: {', '.join(DETECTION_STATUSES)}."
        )
    return candidate


def _active_clause(alias: str) -> str:
    """SQL for 'this suppression still applies': not revoked and not expired.

    Expiry is a read-time test, so an expired suppression stops matching with no
    sweeper. A malformed ``expires_at`` compares as NULL in SQLite and is
    therefore treated as expired, which fails closed.
    """

    prefix = f"{alias}." if alias else ""
    return (
        f"{prefix}revoked_at = '' "
        f"AND ({prefix}expires_at = '' OR datetime({prefix}expires_at) > datetime('now'))"
    )


def _suppression_dict(row: sqlite3.Row) -> dict[str, Any]:
    expires_at = str(row["expires_at"] or "")
    revoked_at = str(row["revoked_at"] or "")
    return {
        "id": int(row["id"]),
        "rule_id": str(row["rule_id"]),
        "host_id": str(row["host_id"]),
        "scope": str(row["scope"]),
        "reason": str(row["reason"]),
        "actor": str(row["actor"]),
        "created_at": str(row["created_at"]),
        "expires_at": expires_at,
        "revoked_at": revoked_at,
        "revoked_by": str(row["revoked_by"] or ""),
        "active": revoked_at == "" and not _is_expired(expires_at),
    }


def _is_expired(expires_at: str) -> bool:
    """True when an expiry has passed (or cannot be read, which fails closed)."""

    if not expires_at:
        return False
    try:
        parsed = datetime.fromisoformat(expires_at)
    except ValueError:
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed <= datetime.now(timezone.utc)


def _clamp_int(value: Any, field: str, minimum: int, maximum: int | None, default: int) -> int:
    """A whole number for paging, clamped to the allowed range."""

    if value is None:
        return default
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a whole number")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be a whole number") from None
    if maximum is not None:
        number = min(number, maximum)
    return max(number, minimum)


def set_status(
    conn: sqlite3.Connection,
    detection: dict[str, Any],
    status: str,
    actor: str,
    assignee: str | None = None,
) -> dict[str, Any]:
    """Move a detection to a new status and record who did it and when.

    Returns the stored state. The previous status, the actor and the timestamp
    are appended to the transition history. ``assignee`` is only changed when it
    is given; otherwise the current owner is left alone. When the new status is
    ``false_positive`` the result carries a ``suppression_offer`` -- a proposal
    only, nothing is created (see :func:`suggest_suppression`).
    """

    host, rule, event = _identity(detection)
    resolved = _normalise_status(status)
    actor = _text(actor, "actor")
    now = _now()

    existing = _state_row(conn, host, rule, event)
    from_status = existing["status"] if existing else "new"
    resolved_assignee = existing["assignee"] if existing else ""
    if assignee is not None:
        resolved_assignee = str(assignee).strip()

    conn.execute(
        "INSERT INTO detection_state(host_id, rule_id, event_id, status, assignee, updated_at, updated_by) "
        "VALUES(?,?,?,?,?,?,?) "
        "ON CONFLICT(host_id, rule_id, event_id) DO UPDATE SET "
        "status = excluded.status, assignee = excluded.assignee, "
        "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
        (host, rule, event, resolved, resolved_assignee, now, actor),
    )
    conn.execute(
        "INSERT INTO detection_transitions(host_id, rule_id, event_id, from_status, to_status, assignee, actor, changed_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (host, rule, event, from_status, resolved, resolved_assignee, actor, now),
    )
    conn.commit()

    state = {
        "host_id": host,
        "rule_id": rule,
        "event_id": event,
        "status": resolved,
        "assignee": resolved_assignee,
        "updated_at": now,
        "updated_by": actor,
    }
    if resolved == "false_positive":
        # Offer, never perform: the analyst applies the offer with suppress().
        state["suppression_offer"] = suggest_suppression(conn, detection)
    return state


def assign(
    conn: sqlite3.Connection,
    detection: dict[str, Any],
    assignee: str,
    actor: str,
) -> dict[str, Any]:
    """Give a detection an owner without changing its status.

    A detection with no state row yet is created in status ``new``. Assignment
    is recorded on the state row (``updated_by``/``updated_at``) but is not a
    status transition, so it does not append to the transition history.
    """

    host, rule, event = _identity(detection)
    resolved_assignee = _text(assignee, "assignee")
    actor = _text(actor, "actor")
    now = _now()

    existing = _state_row(conn, host, rule, event)
    status = existing["status"] if existing else "new"

    conn.execute(
        "INSERT INTO detection_state(host_id, rule_id, event_id, status, assignee, updated_at, updated_by) "
        "VALUES(?,?,?,?,?,?,?) "
        "ON CONFLICT(host_id, rule_id, event_id) DO UPDATE SET "
        "assignee = excluded.assignee, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
        (host, rule, event, status, resolved_assignee, now, actor),
    )
    conn.commit()

    return {
        "host_id": host,
        "rule_id": rule,
        "event_id": event,
        "status": status,
        "assignee": resolved_assignee,
        "updated_at": now,
        "updated_by": actor,
    }


def add_note(
    conn: sqlite3.Connection,
    detection: dict[str, Any],
    author: str,
    text: str,
) -> dict[str, Any]:
    """Append a note to a detection's investigation record.

    Notes are append-only. There is deliberately no update or delete function,
    so an earlier note can never be silently overwritten.
    """

    host, rule, event = _identity(detection)
    author = _text(author, "author")
    body = _text(text, "text")
    now = _now()

    cursor = conn.execute(
        "INSERT INTO detection_notes(host_id, rule_id, event_id, author, body, created_at) "
        "VALUES(?,?,?,?,?,?)",
        (host, rule, event, author, body, now),
    )
    conn.commit()

    return {
        "id": cursor.lastrowid,
        "host_id": host,
        "rule_id": rule,
        "event_id": event,
        "author": author,
        "text": body,
        "created_at": now,
    }


def list_notes(conn: sqlite3.Connection, detection: dict[str, Any]) -> list[dict[str, Any]]:
    """A detection's notes in the order they were written."""

    host, rule, event = _identity(detection)
    rows = _fetchall(
        conn,
        "SELECT id, host_id, rule_id, event_id, author, body, created_at "
        "FROM detection_notes WHERE host_id = ? AND rule_id = ? AND event_id = ? "
        "ORDER BY created_at ASC, id ASC",
        (host, rule, event),
    )
    return [
        {
            "id": int(row["id"]),
            "host_id": str(row["host_id"]),
            "rule_id": str(row["rule_id"]),
            "event_id": str(row["event_id"]),
            "author": str(row["author"]),
            "text": str(row["body"]),
            "created_at": str(row["created_at"]),
        }
        for row in rows
    ]


def list_transitions(conn: sqlite3.Connection, detection: dict[str, Any]) -> list[dict[str, Any]]:
    """A detection's status transitions, oldest first -- the analyst's path."""

    host, rule, event = _identity(detection)
    rows = _fetchall(
        conn,
        "SELECT id, from_status, to_status, assignee, actor, changed_at "
        "FROM detection_transitions WHERE host_id = ? AND rule_id = ? AND event_id = ? "
        "ORDER BY id ASC",
        (host, rule, event),
    )
    return [
        {
            "id": int(row["id"]),
            "from_status": str(row["from_status"]),
            "to_status": str(row["to_status"]),
            "assignee": str(row["assignee"]),
            "actor": str(row["actor"]),
            "changed_at": str(row["changed_at"]),
        }
        for row in rows
    ]


def suppress(
    conn: sqlite3.Connection,
    rule_id: str,
    host_id: str | None = None,
    scope: str = "host",
    reason: str | None = None,
    actor: str = "",
    expires_days: int | None = None,
) -> dict[str, Any]:
    """Create a suppression for a rule, for one host or for every host.

    ``scope="host"`` needs a ``host_id`` and silences the rule on that host
    only; ``scope="global"`` silences it everywhere and must not carry a
    ``host_id``. ``expires_days`` is a positive number of days, or ``None`` for
    a suppression that never expires on its own. Returns the created rule.
    """

    rule_id = _text(rule_id, "rule_id")
    actor = _text(actor, "actor")
    resolved_scope = str(scope or "").strip().lower()
    if resolved_scope not in SUPPRESSION_SCOPES:
        raise ValueError(
            f"Unsupported scope {scope!r}. Expected one of: {', '.join(SUPPRESSION_SCOPES)}."
        )

    if resolved_scope == "host":
        resolved_host = _text(host_id, "host_id for a host-scoped suppression")
    else:
        if host_id not in (None, ""):
            raise ValueError("host_id is only valid with scope='host'")
        resolved_host = ""

    if expires_days is not None:
        if isinstance(expires_days, bool) or not isinstance(expires_days, int) or expires_days <= 0:
            raise ValueError("expires_days must be a positive whole number of days")

    now = _now()
    expires_at = (
        (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()
        if expires_days is not None
        else ""
    )
    reason_text = "" if reason is None else str(reason).strip()

    cursor = conn.execute(
        "INSERT INTO suppressions(rule_id, host_id, scope, reason, actor, created_at, expires_at) "
        "VALUES(?,?,?,?,?,?,?)",
        (rule_id, resolved_host, resolved_scope, reason_text, actor, now, expires_at),
    )
    conn.commit()

    return {
        "id": cursor.lastrowid,
        "rule_id": rule_id,
        "host_id": resolved_host,
        "scope": resolved_scope,
        "reason": reason_text,
        "actor": actor,
        "created_at": now,
        "expires_at": expires_at,
        "revoked_at": "",
        "revoked_by": "",
        "active": True,
    }


def suppression_for(
    conn: sqlite3.Connection,
    host_id: str | None,
    rule_id: str,
) -> dict[str, Any] | None:
    """The active suppression covering (host, rule), or None.

    The most specific match wins: a host-scoped rule beats a global one, and
    among equally specific rules the most recently created wins.
    """

    rule = _text(rule_id, "rule_id")
    host = "" if host_id is None else str(host_id).strip()
    row = _fetchone(
        conn,
        "SELECT * FROM suppressions "
        "WHERE rule_id = ? AND " + _active_clause("") + " "
        "AND (scope = 'global' OR (scope = 'host' AND host_id = ?)) "
        "ORDER BY CASE scope WHEN 'host' THEN 0 ELSE 1 END, id DESC LIMIT 1",
        (rule, host),
    )
    return _suppression_dict(row) if row is not None else None


def is_suppressed(conn: sqlite3.Connection, host_id: str | None, rule_id: str) -> bool:
    """True when an active suppression covers this rule for this host."""

    return suppression_for(conn, host_id, rule_id) is not None


def unsuppress(conn: sqlite3.Connection, suppression_id: int, actor: str) -> dict[str, Any]:
    """Revoke a suppression so it stops applying, recording who revoked it.

    Revoking keeps the row (it is marked revoked rather than deleted) so the
    tuning history survives. Revoking an already-revoked suppression is a no-op
    that returns its current state; an unknown id raises ValueError.
    """

    actor = _text(actor, "actor")
    if isinstance(suppression_id, bool):
        raise ValueError("suppression_id must be a whole number")
    try:
        identifier = int(suppression_id)
    except (TypeError, ValueError):
        raise ValueError("suppression_id must be a whole number") from None

    row = _fetchone(conn, "SELECT * FROM suppressions WHERE id = ?", (identifier,))
    if row is None:
        raise ValueError(f"No suppression with id {identifier}")

    current = _suppression_dict(row)
    if current["revoked_at"]:
        return current

    now = _now()
    conn.execute(
        "UPDATE suppressions SET revoked_at = ?, revoked_by = ? WHERE id = ?",
        (now, actor, identifier),
    )
    conn.commit()
    current["revoked_at"] = now
    current["revoked_by"] = actor
    current["active"] = False
    return current


def list_suppressions(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Every suppression, newest first, each with an ``active`` flag.

    Revoked and expired suppressions are included so the tuning history is
    visible; ``active`` says whether one still applies.
    """

    rows = _fetchall(conn, "SELECT * FROM suppressions ORDER BY id DESC")
    return [_suppression_dict(row) for row in rows]


def suggest_suppression(conn: sqlite3.Connection, detection: dict[str, Any]) -> dict[str, Any] | None:
    """The suppression an analyst could create for a detection, without creating it.

    This only builds the offer. A detection with no rule id names no rule to
    suppress, so the offer is None. ``already_suppressed`` reports whether an
    active rule already covers it. Apply an offer with :func:`suppress`, which
    is a separate, explicit call.
    """

    host, rule, _event = _identity(detection)
    if not rule:
        return None
    existing = suppression_for(conn, host, rule)
    return {
        "rule_id": rule,
        "host_id": host,
        "scope": "host",
        "reason": f"False positive: {rule} on {host}",
        "already_suppressed": existing is not None,
    }


def triage_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    """Count the visible detection queue by status.

    Returns a count for every status plus ``Total`` (the visible queue) and
    ``Suppressed`` (alerts hidden by an active suppression). A detection with no
    state row counts as ``new``.
    """

    ensure_schema(conn)
    counts: dict[str, int] = {status: 0 for status in DETECTION_STATUSES}
    hidden = (
        "NOT EXISTS (SELECT 1 FROM suppressions sup WHERE sup.rule_id = e.rule_id "
        "AND " + _active_clause("sup") + " "
        "AND (sup.scope = 'global' OR (sup.scope = 'host' AND sup.host_id = e.host)))"
    )
    rows = _fetchall(
        conn,
        "SELECT COALESCE(s.status, 'new') AS status, COUNT(*) AS count "
        "FROM live_events e "
        "LEFT JOIN detection_state s ON s.host_id = e.host AND s.rule_id = e.rule_id "
        "AND s.event_id = CAST(e.id AS TEXT) "
        "WHERE e.is_alert = 1 AND " + hidden + " "
        "GROUP BY status",
    )
    for row in rows:
        counts[str(row["status"])] = int(row["count"])

    hidden_row = _fetchone(
        conn,
        "SELECT COUNT(*) AS count FROM live_events e WHERE e.is_alert = 1 "
        "AND EXISTS (SELECT 1 FROM suppressions sup WHERE sup.rule_id = e.rule_id "
        "AND " + _active_clause("sup") + " "
        "AND (sup.scope = 'global' OR (sup.scope = 'host' AND sup.host_id = e.host)))",
    )

    result: dict[str, Any] = dict(counts)
    result["Total"] = sum(counts.values())
    result["Suppressed"] = int(hidden_row["count"])
    return result


def list_detections(
    conn: sqlite3.Connection,
    status: str | None = None,
    host_id: str | None = None,
    assignee: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """The detection queue, filtered and paged, with a total for paging.

    Every row is the stored event plus its triage columns (``status``,
    ``assignee``, ``updated_at``, ``updated_by``). Detections hidden by an
    active suppression are not returned. Ordered by severity, then newest
    first. ``total`` is the count matching the filters before paging.
    """

    ensure_schema(conn)
    resolved_limit = _clamp_int(limit, "limit", 1, 500, 50)
    resolved_offset = _clamp_int(offset, "offset", 0, None, 0)

    clauses = [
        "e.is_alert = 1",
        "NOT EXISTS (SELECT 1 FROM suppressions sup WHERE sup.rule_id = e.rule_id "
        "AND " + _active_clause("sup") + " "
        "AND (sup.scope = 'global' OR (sup.scope = 'host' AND sup.host_id = e.host)))",
    ]
    params: list[Any] = []

    if status is not None:
        clauses.append("COALESCE(s.status, 'new') = ?")
        params.append(_normalise_status(status))
    if host_id is not None and str(host_id).strip():
        clauses.append("e.host = ?")
        params.append(str(host_id).strip())
    if assignee is not None and str(assignee).strip():
        clauses.append("COALESCE(s.assignee, '') = ?")
        params.append(str(assignee).strip())

    where = " WHERE " + " AND ".join(clauses)
    source = (
        "FROM live_events e "
        "LEFT JOIN detection_state s ON s.host_id = e.host AND s.rule_id = e.rule_id "
        "AND s.event_id = CAST(e.id AS TEXT)"
    )

    total_row = _fetchone(conn, "SELECT COUNT(*) AS count " + source + where, tuple(params))
    rows = _fetchall(
        conn,
        "SELECT e.*, COALESCE(s.status, 'new') AS status, COALESCE(s.assignee, '') AS assignee, "
        "COALESCE(s.updated_at, '') AS updated_at, COALESCE(s.updated_by, '') AS updated_by "
        + source
        + where
        + f" ORDER BY {_SEVERITY_ORDER}, datetime(e.timestamp) DESC, e.id DESC LIMIT ? OFFSET ?",
        tuple([*params, resolved_limit, resolved_offset]),
    )

    return {
        "detections": [dict(row) for row in rows],
        "total": int(total_row["count"]),
        "limit": resolved_limit,
        "offset": resolved_offset,
        "count": len(rows),
    }
