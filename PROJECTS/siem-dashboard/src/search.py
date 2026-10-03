"""Indexed event search with a small query language.

The console's first search was a ``LIKE`` scan across ten columns with a limit
and an offset. This module replaces it with a query language and, when the
SQLite build has it, an FTS5 full-text index over the searchable columns. It
owns no data of its own: every function takes a live ``sqlite3.Connection`` and
the caller invokes :func:`ensure_schema` once, exactly as the other modules in
this package do.

Query grammar
-------------
A query is a sequence of whitespace-separated tokens. A token is one of:

* a **free-text term**, e.g. ``failed``;
* a **field clause** ``field:value``, e.g. ``host:LAB-A``;
* either of the above preceded by ``-`` to **negate** it, e.g. ``-host:LAB-A``
  or ``-failed``.

Free-text terms search six columns at once: ``message``, ``rule_name``,
``channel``, ``provider``, ``username`` and ``host``. Every positive free-text
term must match somewhere in those columns; every negated one must match
nowhere in them.

The field names, and the column each filters, are:

=============  =============================================================
``host:``      ``live_events.host``
``host_id:``   ``live_events.host_id``
``severity:``  ``live_events.severity`` (``High``, ``Medium`` or ``Low``)
``channel:``   ``live_events.channel``
``rule:``      ``live_events.rule_name`` **or** ``live_events.rule_id``
``user:``      ``live_events.username``
``source_ip:`` ``live_events.source_ip``
``message:``   ``live_events.message``
``after:``     ``live_events.timestamp``, an **inclusive** lower bound
``before:``    ``live_events.timestamp``, an **exclusive** upper bound
=============  =============================================================

Field names are case-insensitive. ``after:`` and ``before:`` take an ISO-8601
date (``2026-10-01``) or date and time (``2026-10-01 12:30:00`` or
``2026-10-01T12:30:00``), optionally with a trailing ``Z`` or a numeric UTC
offset. A date with no time is midnight UTC. ``after:`` matches events at or
after the instant; ``before:`` matches events strictly before it.

Matching, wildcards and quoting
-------------------------------
``*`` is a wildcard that matches any run of characters and may appear anywhere
in a value. For a **field clause** the value is the whole column pattern:
``host:LAB-A`` matches exactly ``LAB-A``, ``host:LAB*`` matches anything
starting with ``LAB``, and ``message:*failed*`` matches a message containing
``failed``. For a **free-text term** the value is a substring pattern, so
``failed`` matches any searched column containing ``failed`` and ``ad*in``
matches ``admin``.

A value containing spaces, or one that would otherwise be read as a field
clause, is wrapped in double quotes: ``host:"LAB A"`` or ``"http://example"``.
Inside a quoted value a backslash escapes the next character, so ``"a \"b\""``
is the value ``a "b"``. An unclosed quote is an error. A leading ``name:`` is
always read as a field clause, so a free-text term containing a colon must be
quoted, and a value containing spaces must be quoted (a bare ``after:2026-10-01
12:00`` reads ``2026-10-01`` as the date and ``12:00`` as a separate term).

Errors
------
:func:`parse_query` raises ``ValueError`` naming the offending token for an
unknown field, a missing value, a bare ``-``, an unclosed quote, or a date that
cannot be read.

How a query runs, and how honestly that is reported
---------------------------------------------------
:func:`search_events` returns the ``engine`` that actually answered the query:

``fts5``
    The free-text terms were evaluated against an FTS5 full-text index
    (``live_events_fts``). FTS5 indexes whole tokens, not substrings, so a
    free-text term matches a token (case-insensitively, by the FTS5 unicode61
    tokeniser) and a single trailing ``*`` turns it into a prefix query. An
    internal ``*`` (anything other than one trailing ``*``) cannot be expressed
    in an FTS5 query, so a query using one runs on the ``scan`` engine instead.
``scan``
    The query ran as SQL predicates over the columns of ``live_events`` -- the
    fallback path. This is **not** a full-text index: free-text terms become
    ``LIKE`` patterns scanned across the six columns, and the field predicates
    are ordinary ``LIKE`` comparisons; the timestamp bounds compare
    ``live_events.timestamp`` directly, so they can be served by
    ``ix_live_events_timestamp`` while everything else scans. The ``scan``
    engine is used whenever FTS5 is unavailable, whenever
    the index is missing or behind ``live_events``, whenever the query has no
    free-text terms, or whenever a free-text term uses an internal wildcard.

The two engines are not identical: ``scan`` matches substrings and ``fts5``
matches tokens, so ``dmin`` finds ``admin`` on the ``scan`` engine and not on
the ``fts5`` engine, and the same query can return different rows on two
machines. ``engine`` names which one ran rather than hiding that difference.

The FTS5 index
--------------
``live_events_fts`` is a standalone FTS5 table holding its own copy of the six
indexed columns, keyed by the ``live_events.id`` each row came from. Three
triggers on ``live_events`` insert, delete and update the matching index row,
so the index stays in step with changes made through the connection once
:func:`ensure_schema` has run. Rows that already existed when the index was
first created are not indexed until :func:`rebuild_index` is called; a search
whose index is behind the table is answered by the ``scan`` engine rather than
silently returning incomplete results, and :func:`search_summary` reports the
shortfall.

:func:`ensure_schema` creates the index and triggers when the build supports
FTS5, and creates nothing extra when it does not.

Honest limits
-------------
There is no ranking: results are ordered newest first, not by relevance, and
``total`` is an exact count of matches. There is no boolean algebra between
tokens: ``a b`` means *a and b*, tokens are only ever AND-ed, and parentheses
are not part of the grammar. Field-clause matching is case-insensitive for
ASCII only, because it is built on SQLite ``LIKE``. An empty query matches
every event. The index lives in one SQLite file served by one process; it is
not a distributed search service and does not outlive the store it copies.
"""
from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

# The FTS5 virtual table and the triggers that keep it in step with
# ``live_events``. The table name is also what a caller may look for in
# ``sqlite_master``.
FTS_TABLE = "live_events_fts"

# Columns the free-text part searches, in documented order. These are also the
# columns of the FTS5 table.
FREE_TEXT_COLUMNS: tuple[str, ...] = (
    "message",
    "rule_name",
    "channel",
    "provider",
    "username",
    "host",
)

# Every field the grammar accepts, in the order the docstring lists them.
SUPPORTED_FIELDS: tuple[str, ...] = (
    "host",
    "host_id",
    "severity",
    "channel",
    "rule",
    "user",
    "source_ip",
    "message",
    "after",
    "before",
)

# Field clause name -> the single column it filters. ``rule`` is absent because
# it spans two columns; the date fields are absent because they filter the
# timestamp rather than matching text.
_FIELD_COLUMNS: dict[str, str] = {
    "host": "host",
    "host_id": "host_id",
    "severity": "severity",
    "channel": "channel",
    "user": "username",
    "source_ip": "source_ip",
    "message": "message",
}
_RULE_FIELD = "rule"
_DATE_FIELDS = ("after", "before")

# A field clause starts with a name followed by a colon. The colon may only
# follow a name, which is what keeps a free-text term from being mistaken for a
# clause unless it really looks like ``name:``.
_FIELD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*:")

# An ISO-8601 date, optionally with a time and an optional ``Z`` or numeric
# offset. Deliberately strict: ``20261001`` is rejected even though
# ``datetime.fromisoformat`` would accept it.
_DATE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}"
    r"(?:[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?$"
)

_FTS_SCHEMA: tuple[str, ...] = (
    "CREATE VIRTUAL TABLE IF NOT EXISTS live_events_fts USING fts5("
    + ", ".join(FREE_TEXT_COLUMNS)
    + ")",
    "CREATE TRIGGER IF NOT EXISTS search_events_ai AFTER INSERT ON live_events BEGIN "
    "INSERT INTO live_events_fts(rowid, " + ", ".join(FREE_TEXT_COLUMNS) + ") "
    "VALUES (new.id, " + ", ".join(f"new.{column}" for column in FREE_TEXT_COLUMNS) + "); END",
    "CREATE TRIGGER IF NOT EXISTS search_events_ad AFTER DELETE ON live_events BEGIN "
    "DELETE FROM live_events_fts WHERE rowid = old.id; END",
    "CREATE TRIGGER IF NOT EXISTS search_events_au AFTER UPDATE ON live_events BEGIN "
    "DELETE FROM live_events_fts WHERE rowid = old.id; "
    "INSERT INTO live_events_fts(rowid, " + ", ".join(FREE_TEXT_COLUMNS) + ") "
    "VALUES (new.id, " + ", ".join(f"new.{column}" for column in FREE_TEXT_COLUMNS) + "); END",
)

# Whether this process's SQLite build can create an FTS5 table. Probed once;
# ``None`` means "not asked yet".
_FTS5_SUPPORTED: bool | None = None


def fts5_supported(conn: sqlite3.Connection) -> bool:
    """True when this SQLite build can create an FTS5 table.

    Probed once by creating and dropping a temporary FTS5 table, then
    remembered for the process. A test that needs the fallback path can replace
    this function (``monkeypatch.setattr(search, "fts5_supported", ...)``) so a
    build without FTS5 does not have to be installed to exercise it.
    """

    global _FTS5_SUPPORTED
    if _FTS5_SUPPORTED is None:
        try:
            conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS temp.__search_fts5_probe USING fts5(x)"
            )
            conn.execute("DROP TABLE IF EXISTS temp.__search_fts5_probe")
        except sqlite3.OperationalError:
            _FTS5_SUPPORTED = False
        else:
            _FTS5_SUPPORTED = True
    return _FTS5_SUPPORTED


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the FTS5 index and its triggers when the build supports FTS5.

    Idempotent and safe to call on every request. When FTS5 is unavailable this
    creates nothing: the ``scan`` engine needs no new schema. It also points the
    connection at ``sqlite3.Row`` when nothing else has, so reads below can
    address columns by name.
    """

    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row
    if fts5_supported(conn):
        for statement in _FTS_SCHEMA:
            conn.execute(statement)
    conn.commit()


def _read_value(text: str, index: int, token_start: int) -> tuple[str, int]:
    """Read a value from ``index``, honouring double-quoted runs.

    Returns the value and the index just past it. A quoted run may contain
    spaces and colons; a backslash inside it escapes the next character.
    """

    length = len(text)
    out: list[str] = []
    while index < length and not text[index].isspace():
        char = text[index]
        if char == '"':
            index += 1
            closed = False
            while index < length:
                inner = text[index]
                if inner == "\\" and index + 1 < length:
                    out.append(text[index + 1])
                    index += 2
                    continue
                if inner == '"':
                    closed = True
                    index += 1
                    break
                out.append(inner)
                index += 1
            if not closed:
                raise ValueError(f"Unclosed quote in token {text[token_start:]!r}")
        else:
            out.append(char)
            index += 1
    return "".join(out), index


def _parse_date(value: str, token: str) -> str:
    """Return an ``after:``/``before:`` value as a stored UTC timestamp.

    Accepts a date or a date and time, with an optional ``Z`` or numeric offset,
    and normalises it to ``YYYY-MM-DD HH:MM:SS`` UTC -- the form the event store
    writes -- so it compares directly against ``live_events.timestamp``.
    """

    if "*" in value:
        raise ValueError(
            f"Invalid date {value!r} in token {token!r}: a date cannot contain '*'."
        )
    candidate = value.strip()
    if not _DATE_RE.match(candidate):
        raise ValueError(
            f"Invalid date {value!r} in token {token!r}. "
            "Expected YYYY-MM-DD or YYYY-MM-DD HH:MM:SS."
        )
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(
            f"Invalid date {value!r} in token {token!r}. "
            "Expected YYYY-MM-DD or YYYY-MM-DD HH:MM:SS."
        ) from None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def parse_query(text: str) -> dict[str, Any]:
    """Parse a query string into free-text terms and field clauses.

    Returns ``{"raw": text, "terms": [...], "clauses": [...]}`` where each term
    is ``{"value": str, "negated": bool}`` and each clause is ``{"field": str,
    "value": str, "negated": bool, "kind": "text"|"date"}`` (a date clause also
    carries ``raw_value``, the value before it was normalised). Raises
    ``ValueError`` naming the offending token for malformed input.
    """

    if not isinstance(text, str):
        raise ValueError("query must be a string")

    terms: list[dict[str, Any]] = []
    clauses: list[dict[str, Any]] = []
    index = 0
    length = len(text)

    while index < length:
        if text[index].isspace():
            index += 1
            continue

        token_start = index
        negated = False
        if text[index] == "-":
            negated = True
            index += 1
            if index >= length or text[index].isspace():
                raise ValueError(
                    f"Token {text[token_start:]!r} is a bare '-'; a '-' must be "
                    "followed by a term or a field clause."
                )

        match = _FIELD_RE.match(text, index)
        if match is not None:
            field = match.group(0)[:-1].lower()
            index = match.end()
            value, index = _read_value(text, index, token_start)
            token = text[token_start:index]
            if field not in SUPPORTED_FIELDS:
                raise ValueError(
                    f"Unknown field {field!r} in token {token!r}. "
                    f"Supported fields: {', '.join(SUPPORTED_FIELDS)}."
                )
            if not value:
                raise ValueError(f"Missing value for field {field!r} in token {token!r}.")
            if field in _DATE_FIELDS:
                clauses.append(
                    {
                        "field": field,
                        "value": _parse_date(value, token),
                        "raw_value": value,
                        "negated": negated,
                        "kind": "date",
                    }
                )
            else:
                clauses.append(
                    {"field": field, "value": value, "negated": negated, "kind": "text"}
                )
        else:
            value, index = _read_value(text, index, token_start)
            token = text[token_start:index]
            if not value:
                raise ValueError(f"Empty term in token {token!r}.")
            terms.append({"value": value, "negated": negated})

    return {"raw": text, "terms": terms, "clauses": clauses}


def _glob_to_like(value: str, *, wrap: bool) -> str:
    """Turn a ``*``-glob value into a ``LIKE`` pattern, escaping metacharacters.

    ``*`` becomes ``%``; a literal backslash, ``%`` or ``_`` is escaped for
    ``ESCAPE '\\'``. ``wrap`` surrounds the pattern with ``%`` for the substring
    matching a free-text term uses.
    """

    parts: list[str] = []
    for char in value:
        if char == "*":
            parts.append("%")
        elif char in ("\\", "%", "_"):
            parts.append("\\" + char)
        else:
            parts.append(char)
    pattern = "".join(parts)
    return f"%{pattern}%" if wrap else pattern


def _field_conditions(parsed: dict[str, Any]) -> tuple[list[str], list[Any]]:
    """SQL predicates for the field clauses, shared by both engines."""

    conditions: list[str] = []
    params: list[Any] = []
    for clause in parsed["clauses"]:
        field = clause["field"]
        if clause["kind"] == "date":
            # Timestamps are stored as fixed-width ``YYYY-MM-DD HH:MM:SS`` UTC,
            # so a string comparison is chronological and can use
            # ``ix_live_events_timestamp``. ``after`` is inclusive, ``before``
            # exclusive.
            operator = ">=" if field == "after" else "<"
            condition = f"e.timestamp {operator} ?"
            params.append(clause["value"])
        else:
            pattern = _glob_to_like(clause["value"], wrap=False)
            if field == _RULE_FIELD:
                condition = (
                    "(e.rule_name LIKE ? ESCAPE '\\' OR e.rule_id LIKE ? ESCAPE '\\')"
                )
                params.extend((pattern, pattern))
            else:
                condition = f"e.{_FIELD_COLUMNS[field]} LIKE ? ESCAPE '\\'"
                params.append(pattern)
        conditions.append(f"NOT ({condition})" if clause["negated"] else condition)
    return conditions, params


def _scan_conditions(parsed: dict[str, Any]) -> tuple[list[str], list[Any]]:
    """SQL predicates for the free-text terms on the scan engine."""

    conditions: list[str] = []
    params: list[Any] = []
    for term in parsed["terms"]:
        pattern = _glob_to_like(term["value"], wrap=True)
        alternatives = " OR ".join(
            f"e.{column} LIKE ? ESCAPE '\\'" for column in FREE_TEXT_COLUMNS
        )
        condition = f"({alternatives})"
        params.extend([pattern] * len(FREE_TEXT_COLUMNS))
        conditions.append(f"NOT ({condition})" if term["negated"] else condition)
    return conditions, params


def _fts_expressible(value: str) -> bool:
    """True when a free-text term can be written as an FTS5 query.

    FTS5 supports a single trailing ``*`` (a prefix query) but no internal
    wildcard, and a value that is nothing but a wildcard has no term to index.
    """

    core = value[:-1] if value.endswith("*") else value
    return bool(core) and "*" not in core


def _fts_term(value: str) -> str:
    """A free-text term as an FTS5 query string, safely quoted.

    The term is wrapped in double quotes (with internal quotes doubled) so it
    cannot be read as FTS5 query syntax; a trailing ``*`` is placed outside the
    quotes to make it a prefix query.
    """

    prefix = value.endswith("*")
    core = value[:-1] if prefix else value
    quoted = '"' + core.replace('"', '""') + '"'
    return quoted + "*" if prefix else quoted


def _fts_conditions(parsed: dict[str, Any]) -> tuple[list[str], list[Any]]:
    """SQL predicates that push the free-text terms into the FTS5 index."""

    conditions: list[str] = []
    params: list[Any] = []
    positive = [term["value"] for term in parsed["terms"] if not term["negated"]]
    if positive:
        conditions.append(
            "e.id IN (SELECT rowid FROM live_events_fts WHERE live_events_fts MATCH ?)"
        )
        params.append(" ".join(_fts_term(value) for value in positive))
    for term in parsed["terms"]:
        if term["negated"]:
            conditions.append(
                "e.id NOT IN (SELECT rowid FROM live_events_fts WHERE live_events_fts MATCH ?)"
            )
            params.append(_fts_term(term["value"]))
    return conditions, params


def _index_exists(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (FTS_TABLE,)
    ).fetchone()
    return row is not None


def _count(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> int:
    return int(conn.execute(sql, params).fetchone()[0])


def _index_behind(conn: sqlite3.Connection) -> bool:
    """True when the index holds fewer rows than ``live_events``.

    A short index would make an FTS5 search miss rows that exist, so it is
    treated as a reason to fall back to the scan engine rather than a reason to
    return incomplete results.
    """

    if not _index_exists(conn):
        return False
    indexed = _count(conn, f"SELECT COUNT(*) FROM {FTS_TABLE}")
    total = _count(conn, "SELECT COUNT(*) FROM live_events")
    return indexed < total


def _choose_engine(conn: sqlite3.Connection, parsed: dict[str, Any]) -> str:
    """Decide, and name, how a parsed query will run."""

    if not parsed["terms"]:
        return "scan"
    if not fts5_supported(conn):
        return "scan"
    if not _index_exists(conn):
        return "scan"
    if not all(_fts_expressible(term["value"]) for term in parsed["terms"]):
        return "scan"
    if _index_behind(conn):
        return "scan"
    return "fts5"


def _whole_number(value: Any, field: str, minimum: int) -> int:
    """A whole number at or above ``minimum``, or a ValueError naming it."""

    if isinstance(value, bool):
        raise ValueError(f"{field} must be a whole number")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be a whole number") from None
    if number < minimum:
        raise ValueError(f"{field} must be at least {minimum}")
    return number


def search_events(
    conn: sqlite3.Connection,
    query: str,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Run a query against stored events and page the matches.

    Returns ``{"events": [...], "total": int, "parsed": {...}, "engine": str}``.
    ``total`` counts every match, not just the page. ``engine`` is ``"fts5"``
    when the free-text part ran against the FTS5 index and ``"scan"`` when the
    whole query ran as column predicates over ``live_events`` (see the module
    docstring). ``limit`` and ``offset`` must be whole numbers, ``limit`` at
    least 1 and ``offset`` at least 0, or ``ValueError`` is raised.
    """

    parsed = parse_query(query)
    resolved_limit = _whole_number(limit, "limit", 1)
    resolved_offset = _whole_number(offset, "offset", 0)

    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row

    engine = _choose_engine(conn, parsed)
    if engine == "fts5":
        conditions, params = _fts_conditions(parsed)
    else:
        conditions, params = _scan_conditions(parsed)
    field_conditions, field_params = _field_conditions(parsed)
    conditions.extend(field_conditions)
    params.extend(field_params)
    where = " AND ".join(conditions) if conditions else "1 = 1"

    total = _count(conn, f"SELECT COUNT(*) FROM live_events e WHERE {where}", tuple(params))
    rows = conn.execute(
        f"SELECT e.* FROM live_events e WHERE {where} "
        "ORDER BY e.timestamp DESC, e.id DESC LIMIT ? OFFSET ?",
        (*params, resolved_limit, resolved_offset),
    ).fetchall()

    return {
        "events": [dict(row) for row in rows],
        "total": total,
        "parsed": parsed,
        "engine": engine,
    }


def search_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    """Describe the search index's state.

    Returns ``{"fts5_available", "index_exists", "indexed_events",
    "events_total", "index_behind"}``. ``indexed_events`` is how many rows the
    FTS5 index holds (0 when there is no index); ``events_total`` is how many
    events are stored; ``index_behind`` is true when the index holds fewer than
    the table, which is the state :func:`rebuild_index` fixes.
    """

    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row

    available = fts5_supported(conn)
    exists = _index_exists(conn)
    total = _count(conn, "SELECT COUNT(*) FROM live_events")
    indexed = _count(conn, f"SELECT COUNT(*) FROM {FTS_TABLE}") if exists else 0

    return {
        "fts5_available": available,
        "index_exists": exists,
        "indexed_events": indexed,
        "events_total": total,
        "index_behind": exists and indexed < total,
    }


def rebuild_index(conn: sqlite3.Connection) -> dict[str, Any]:
    """Populate or repopulate the FTS5 index from ``live_events``.

    Creates the index and triggers if they are missing, then replaces the index
    contents with one row per stored event. Returns ``{"fts5_available",
    "index_exists", "rows_processed", "indexed_events"}``; ``rows_processed`` is
    how many stored events were read and written to the index. When the build
    has no FTS5 there is nothing to build, and the result reports that with zero
    rows rather than raising.
    """

    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row

    if not fts5_supported(conn):
        return {
            "fts5_available": False,
            "index_exists": False,
            "rows_processed": 0,
            "indexed_events": 0,
        }

    for statement in _FTS_SCHEMA:
        conn.execute(statement)

    total = _count(conn, "SELECT COUNT(*) FROM live_events")
    conn.execute(f"DELETE FROM {FTS_TABLE}")
    conn.execute(
        f"INSERT INTO {FTS_TABLE}(rowid, {', '.join(FREE_TEXT_COLUMNS)}) "
        f"SELECT id, {', '.join(FREE_TEXT_COLUMNS)} FROM live_events"
    )
    conn.commit()
    indexed = _count(conn, f"SELECT COUNT(*) FROM {FTS_TABLE}")

    return {
        "fts5_available": True,
        "index_exists": True,
        "rows_processed": total,
        "indexed_events": indexed,
    }
