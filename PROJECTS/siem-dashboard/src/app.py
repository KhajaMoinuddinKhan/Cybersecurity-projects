"""Local SIEM console backed by live event data.

The pipeline is collect, classify, store, correlate, present. Classification is
done by the rule engine in ``rules.py``, which reads rules from files rather
than from this module; correlation is done by ``correlation.py``, which looks
for sequences across stored alerts. This module owns storage, the HTTP surface
and the operational concerns: retention, authentication and notification.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sqlite3
import ssl
import threading
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from . import auth, backup, baseline, hosts, schema, search, security, triage
from .correlation import CORRELATION_SOURCE, correlate
from .enrichment import ThreatIntel, apply_enrichment
from .notify import Notifier
from .rules import RuleEngine, RuleError, shared_engine
from .windows_collector import WindowsEventCollector

VALID_SEVERITIES = ("High", "Medium", "Low")

# Name of the cookie carrying a signed-in user's session token.
SESSION_COOKIE = "siem_session"


def backup_directory(db_path: Path) -> Path:
    """Where snapshots of this store are written.

    Beside the database rather than inside it, so a backup is never part of what
    it is copying.
    """

    return Path(db_path).parent / f"{Path(db_path).stem}-backups"

# Ten years in minutes. SQLite cannot represent a window beyond its own date
# range, so a larger value used to match no events at all.
MAX_SINCE_MINUTES = 5_256_000

SCHEMA = """CREATE TABLE IF NOT EXISTS live_events (
id INTEGER PRIMARY KEY AUTOINCREMENT,
timestamp TEXT NOT NULL,
channel TEXT NOT NULL,
provider TEXT NOT NULL,
event_id TEXT NOT NULL,
level TEXT NOT NULL,
severity TEXT NOT NULL,
username TEXT NOT NULL,
host TEXT NOT NULL,
source_ip TEXT NOT NULL,
message TEXT NOT NULL,
record_id TEXT NOT NULL,
source TEXT NOT NULL,
is_alert INTEGER NOT NULL DEFAULT 0,
rule_name TEXT NOT NULL DEFAULT '',
raw_log TEXT NOT NULL DEFAULT '',
external_id TEXT NOT NULL DEFAULT '',
rule_id TEXT NOT NULL DEFAULT '',
techniques TEXT NOT NULL DEFAULT '',
matched_on TEXT NOT NULL DEFAULT '',
enrichment TEXT NOT NULL DEFAULT '',
created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)"""

# Columns added after the first release. An existing store is upgraded in place
# rather than being dropped, because the events in it are the record.
MIGRATIONS = (
    ("rule_id", "ALTER TABLE live_events ADD COLUMN rule_id TEXT NOT NULL DEFAULT ''"),
    ("techniques", "ALTER TABLE live_events ADD COLUMN techniques TEXT NOT NULL DEFAULT ''"),
    ("matched_on", "ALTER TABLE live_events ADD COLUMN matched_on TEXT NOT NULL DEFAULT ''"),
    ("enrichment", "ALTER TABLE live_events ADD COLUMN enrichment TEXT NOT NULL DEFAULT ''"),
    ("host_id", "ALTER TABLE live_events ADD COLUMN host_id TEXT NOT NULL DEFAULT ''"),
)

DEFAULT_RETAIN_DAYS = 30

# A second bound, by volume. Age alone is not enough: Sysmon on a working laptop
# produced about 63 events a minute after tuning, which is 91,000 a day and
# roughly 6.8 GB over a 30-day window. On a machine with 33 GB free that is a
# problem the age limit never sees. Whichever limit is reached first wins.
DEFAULT_MAX_DB_MB = 500


class _Unset:
    """Sentinel: 'the caller did not say', as distinct from 'use none'."""


_UNSET = _Unset()

_intel: ThreatIntel | None = None


def default_engine() -> RuleEngine:
    """The rule engine for the rules shipped with this project."""

    return shared_engine()


def set_intel(intel: ThreatIntel) -> None:
    """Point the pipeline at a threat-intelligence store."""

    global _intel
    _intel = intel


def default_intel() -> ThreatIntel:
    return _intel if _intel is not None else ThreatIntel({})


def get_connection(db_path: Path) -> sqlite3.Connection:
    """Open the live event store and bring its schema up to date."""

    connection = sqlite3.connect(db_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute(SCHEMA)

    # Bring an older store up to date before anything indexes the new columns.
    existing = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(live_events)").fetchall()
    }
    for column, statement in MIGRATIONS:
        if column not in existing:
            connection.execute(statement)

    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_live_events_external "
        "ON live_events(source, external_id) WHERE external_id != ''"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS ix_live_events_timestamp "
        "ON live_events(timestamp)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS ix_live_events_alert "
        "ON live_events(is_alert, severity)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS ix_live_events_rule "
        "ON live_events(rule_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS ix_live_events_host_id "
        "ON live_events(host_id)"
    )

    # Accounts, the host registry and the triage tables live in the same store,
    # so a single file is still the whole console's state.
    auth.ensure_schema(connection)
    hosts.ensure_schema(connection)
    triage.ensure_schema(connection)
    security.ensure_schema(connection)
    baseline.ensure_schema(connection)
    search.ensure_schema(connection)

    connection.commit()
    return connection


def normalise_severity(value: str | None) -> str:
    """Return a supported severity."""

    candidate = (value or "Low").strip().title()
    if candidate not in VALID_SEVERITIES:
        raise ValueError(
            f"Unsupported severity {value!r}. Expected High, Medium, or Low."
        )
    return candidate


def normalise_timestamp(value: Any) -> str:
    """Store timestamps as UTC without a timezone suffix for SQLite queries."""

    if value is None or not str(value).strip():
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid timestamp: {text}") from exc

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def _techniques_text(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    return str(value or "")


def _json_text(value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def normalise_payload(
    payload: dict[str, Any],
    source_default: str = "api",
) -> tuple[Any, ...]:
    """Convert a collector, API, or imported event into one database row."""

    if not isinstance(payload, dict):
        raise ValueError("Each event must be a JSON object")
    alert = payload.get("is_alert", False)
    if not isinstance(alert, bool):
        raise ValueError("is_alert must be a JSON boolean")
    message = str(payload.get("message") or payload.get("event") or "").strip()
    if not message:
        raise ValueError("Event payload needs a 'message' or 'event' value")

    raw_log = payload.get("raw_log")
    if raw_log is None:
        raw_log = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    elif not isinstance(raw_log, str):
        # Keep a supplied structured raw record as JSON, not a Python repr.
        raw_log = json.dumps(raw_log, ensure_ascii=False, sort_keys=True)

    return (
        normalise_timestamp(payload.get("timestamp")),
        str(payload.get("channel") or payload.get("source") or source_default).strip(),
        str(payload.get("provider") or "unknown").strip(),
        str(payload.get("event_id") or payload.get("id") or "unknown").strip(),
        str(payload.get("level") or "Information").strip(),
        normalise_severity(str(payload.get("severity") or "Low")),
        str(payload.get("username") or payload.get("user") or "unknown").strip(),
        str(payload.get("host") or payload.get("hostname") or "unknown").strip(),
        str(payload.get("source_ip") or payload.get("ip") or "local").strip(),
        message,
        str(payload.get("record_id") or "").strip(),
        str(payload.get("source") or source_default).strip(),
        1 if alert else 0,
        str(payload.get("rule_name") or "").strip(),
        str(raw_log),
        str(payload.get("external_id") or "").strip(),
        str(payload.get("rule_id") or "").strip(),
        _techniques_text(payload.get("techniques")),
        _json_text(payload.get("matched_on")),
        _json_text(payload.get("enrichment")),
        # Which enrolled host this came from. Empty for anything that arrived
        # without going through an agent, which is how local events look.
        str(payload.get("host_id") or "").strip(),
    )


INSERT_SQL = """INSERT OR IGNORE INTO live_events(
    timestamp,channel,provider,event_id,level,severity,username,host,
    source_ip,message,record_id,source,is_alert,rule_name,raw_log,external_id,
    rule_id,techniques,matched_on,enrichment,host_id
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""


def classify_payloads(
    payloads: Iterable[dict[str, Any]],
    *,
    engine: RuleEngine | None,
    intel: ThreatIntel,
) -> list[dict[str, Any]]:
    """Apply threat intelligence and the rule engine to events before storage.

    An event that already declares itself an alert keeps the severity its source
    gave it; the rule engine records which rule also matched without overruling
    the judgement that was already made.
    """

    judged: list[dict[str, Any]] = []

    for original in payloads:
        payload = original
        if intel.size:
            payload = apply_enrichment(payload, intel)

        if engine is None:
            judged.append(payload)
            continue

        match = engine.match(payload)
        if match is None:
            judged.append(payload)
            continue

        already_judged = bool(payload.get("is_alert"))
        updated = dict(payload)
        updated["rule_id"] = match.rule_id
        updated["rule_name"] = match.title
        updated["techniques"] = list(match.techniques)
        updated["matched_on"] = list(match.matched_on)
        if not already_judged and match.raises_alert:
            updated["is_alert"] = True
            updated["severity"] = match.severity
        judged.append(updated)

    return judged


def notification_record(payload: dict[str, Any], source_default: str) -> dict[str, Any]:
    """The alert as a notification sees it.

    Uses the same defaults the stored row does, so a webhook or log line does
    not report ``None`` for a field the database filled in.
    """

    return {
        "is_alert": bool(payload.get("is_alert")),
        "severity": str(payload.get("severity") or "Low"),
        "timestamp": payload.get("timestamp"),
        "rule_id": str(payload.get("rule_id") or ""),
        "rule_name": str(payload.get("rule_name") or ""),
        "techniques": _techniques_text(payload.get("techniques")),
        "host": str(payload.get("host") or payload.get("hostname") or "unknown"),
        "username": str(payload.get("username") or payload.get("user") or "unknown"),
        "source_ip": str(payload.get("source_ip") or payload.get("ip") or "local"),
        "channel": str(payload.get("channel") or payload.get("source") or source_default),
        "event_id": str(payload.get("event_id") or payload.get("id") or "unknown"),
        "message": str(payload.get("message") or payload.get("event") or ""),
        "source": str(payload.get("source") or source_default),
    }


def ingest_payloads(
    db_path: Path,
    payloads: Iterable[dict[str, Any]],
    source_default: str = "api",
    *,
    engine: Any = _UNSET,
    intel: Any = _UNSET,
    notifier: Notifier | None = None,
) -> int:
    """Classify, enrich, and store events. Returns the number actually stored.

    Duplicates are absorbed by a unique index on (source, external_id), so
    re-running an import or re-reading a channel is safe.
    """

    resolved_engine = default_engine() if isinstance(engine, _Unset) else engine
    resolved_intel = default_intel() if isinstance(intel, _Unset) else intel

    judged = classify_payloads(payloads, engine=resolved_engine, intel=resolved_intel)
    rows = [normalise_payload(payload, source_default) for payload in judged]
    if not rows:
        return 0

    with closing(get_connection(db_path)) as connection, connection:
        # Counted from the statement's own row count, not from total_changes:
        # the search index is kept in step by triggers on this table, and
        # total_changes includes what a trigger writes, which reported four
        # stored events for every one that was actually stored.
        inserted = connection.executemany(INSERT_SQL, rows).rowcount

    if notifier is not None and inserted:
        notifier.deliver(
            [notification_record(payload, source_default) for payload in judged]
        )

    return inserted


def parse_event_file(filename: str, content: bytes) -> list[dict[str, Any]]:
    """Read JSON, JSONL, NDJSON, or CSV event data."""

    if len(content) > 3_000_000:
        raise ValueError("Import file is too large. Keep it under 3 MB.")

    suffix = Path(filename).suffix.lower()
    text = content.decode("utf-8-sig")

    if suffix == ".json":
        try:
            data = json.loads(text)
        except RecursionError as exc:
            raise ValueError("JSON is nested too deeply to import") from exc
        if isinstance(data, dict) and "events" in data:
            data = data["events"]
        elif isinstance(data, dict):
            data = [data]
        if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
            raise ValueError("JSON must contain an event object or a list of event objects")
        return data

    if suffix in {".jsonl", ".ndjson"}:
        rows: list[dict[str, Any]] = []
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except RecursionError as exc:
                raise ValueError("JSON is nested too deeply to import") from exc
            if not isinstance(item, dict):
                raise ValueError(f"Line {line_number} is not a JSON object")
            rows.append(item)
        return rows

    if suffix == ".csv":
        # Match the CSV reader's field limit to the request cap so wide message
        # fields import instead of raising an uncaught csv.Error.
        csv.field_size_limit(3_000_000)
        try:
            reader = csv.DictReader(io.StringIO(text))
            fields = reader.fieldnames or []
            if not fields or any(not field.strip() for field in fields) or len(set(fields)) != len(fields):
                raise ValueError("CSV needs unique, nonempty column names")
            rows = [dict(row) for row in reader]
        except csv.Error as exc:
            raise ValueError(f"CSV could not be read: {exc}") from exc
        if any(None in row or any(value is None for value in row.values()) for row in rows):
            raise ValueError("CSV rows must have the same number of columns as the header")
        for row in rows:
            if "is_alert" in row:
                value = str(row["is_alert"]).strip().lower()
                if value not in {"true", "false", "1", "0", ""}:
                    raise ValueError("CSV is_alert must be true, false, 1, or 0")
                row["is_alert"] = value in {"true", "1"}
        return rows

    raise ValueError("Supported imports: .json, .jsonl, .ndjson, and .csv")


def reset_events(db_path: Path) -> None:
    """Clear the live event store."""

    with closing(get_connection(db_path)) as connection, connection:
        connection.execute("DELETE FROM live_events")
        connection.execute("DELETE FROM sqlite_sequence WHERE name = 'live_events'")


def prune_events(db_path: Path, retain_days: int) -> int:
    """Delete events older than the retention window.

    Correlation alerts are kept for the same window as everything else: a
    sequence finding is only useful while the events behind it are still there
    to be checked.
    """

    if retain_days <= 0:
        return 0

    cutoff = (datetime.now(timezone.utc) - timedelta(days=retain_days)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    with closing(get_connection(db_path)) as connection, connection:
        # Row count rather than total_changes, for the same reason as ingestion:
        # the delete triggers on this table would otherwise be counted too.
        return connection.execute(
            "DELETE FROM live_events WHERE datetime(timestamp) < datetime(?)",
            (cutoff,),
        ).rowcount


def database_size_mb(db_path: Path) -> float:
    """The size of the store on disk, including its write-ahead log."""

    total = 0
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(f"{db_path}{suffix}")
        if candidate.exists():
            total += candidate.stat().st_size
    return round(total / (1024 * 1024), 2)


def prune_to_size(db_path: Path, max_mb: int) -> int:
    """Delete the oldest events until the store is under a size cap.

    The row count to remove is estimated from the current bytes per row, then
    the space is reclaimed with a vacuum, because deleting rows in SQLite frees
    pages for reuse without shrinking the file. The vacuum is the expensive part
    and only runs when something was actually deleted.
    """

    if max_mb <= 0:
        return 0

    path = Path(db_path)
    limit_bytes = max_mb * 1024 * 1024
    if not path.exists() or database_size_mb(db_path) * 1024 * 1024 <= limit_bytes:
        return 0

    with closing(get_connection(db_path)) as connection, connection:
        total = int(connection.execute("SELECT COUNT(*) FROM live_events").fetchone()[0])
        if total == 0:
            return 0
        bytes_per_row = max(1.0, path.stat().st_size / total)
        target_rows = int(limit_bytes / bytes_per_row)
        excess = total - target_rows
        if excess <= 0:
            return 0
        connection.execute(
            "DELETE FROM live_events WHERE id IN ("
            " SELECT id FROM live_events ORDER BY datetime(timestamp) ASC, id ASC LIMIT ?)",
            (excess,),
        )

    with closing(sqlite3.connect(path)) as vacuum:
        vacuum.execute("VACUUM")
    return excess


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def tls_context(cert: Path | None, key: Path | None) -> tuple[str, str] | None:
    """Return Flask's ``ssl_context`` for a certificate pair, or None.

    HTTPS is opt-in: the console serves plain HTTP unless both a certificate and
    its key are given. The pair is loaded here so a wrong path or a key that does
    not match its certificate fails at start-up with a sentence rather than at
    the first connection with a traceback.
    """

    if cert is None and key is None:
        return None
    if cert is None or key is None:
        raise ValueError(
            "HTTPS needs both --tls-cert and --tls-key; give both or neither."
        )
    for path, label in ((cert, "certificate"), (key, "key")):
        if not Path(path).is_file():
            raise ValueError(f"TLS {label} not found: {path}")
    probe = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        probe.load_cert_chain(str(cert), str(key))
    except ssl.SSLError as exc:
        raise ValueError(f"Could not load the TLS certificate and key: {exc}") from exc
    return (str(cert), str(key))


def _whole_number(value: Any, default: int) -> int:
    """A whole number from a query string, falling back to the default.

    Paging parameters come from the address bar, so a mistyped one should give
    the default page rather than an error.
    """

    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _as_bool(value: str | None) -> bool:
    """Accept the common true spellings for a boolean query parameter."""

    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _filters(
    severity: str | None = None,
    search: str | None = None,
    channel: str | None = None,
    provider: str | None = None,
    event_id: str | None = None,
    username: str | None = None,
    since_minutes: int | None = None,
    alerts_only: bool = False,
    rule_id: str | None = None,
    rule_matched: bool = False,
) -> tuple[list[str], list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []

    if severity:
        clauses.append("severity = ?")
        params.append(normalise_severity(severity))

    if search and search.strip():
        pattern = f"%{_escape_like(search.strip())}%"
        clauses.append(
            "(message LIKE ? ESCAPE '\\' OR provider LIKE ? ESCAPE '\\' "
            "OR event_id LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\' "
            "OR host LIKE ? ESCAPE '\\' OR source_ip LIKE ? ESCAPE '\\' "
            "OR channel LIKE ? ESCAPE '\\' OR rule_name LIKE ? ESCAPE '\\' "
            "OR rule_id LIKE ? ESCAPE '\\' OR techniques LIKE ? ESCAPE '\\')"
        )
        params.extend([pattern] * 10)

    for column, value in (
        ("channel", channel),
        ("provider", provider),
        ("event_id", event_id),
        ("username", username),
        ("rule_id", rule_id),
    ):
        if value and value.strip():
            clauses.append(f"{column} = ?")
            params.append(value.strip())

    if since_minutes is not None:
        clauses.append("datetime(timestamp) >= datetime('now', ?)")
        params.append(f"-{since_minutes} minutes")

    if alerts_only:
        clauses.append("is_alert = 1")

    # Correlation matches on rule hits, not on alerts: a rule marked alert: false
    # still names the behaviour a sequence is built from.
    if rule_matched:
        clauses.append("rule_id != ''")

    return clauses, params


def _where(clauses: list[str]) -> str:
    return " WHERE " + " AND ".join(clauses) if clauses else ""


def query_events(
    db_path: Path,
    *,
    severity: str | None = None,
    search: str | None = None,
    channel: str | None = None,
    provider: str | None = None,
    event_id: str | None = None,
    username: str | None = None,
    since_minutes: int | None = None,
    alerts_only: bool = False,
    rule_id: str | None = None,
    rule_matched: bool = False,
    limit: int = 300,
) -> list[dict[str, Any]]:
    """Return live events matching the active filters."""

    clauses, params = _filters(
        severity,
        search,
        channel,
        provider,
        event_id,
        username,
        since_minutes,
        alerts_only,
        rule_id,
        rule_matched,
    )
    query = "SELECT * FROM live_events" + _where(clauses)
    query += " ORDER BY datetime(timestamp) DESC, id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 2000)))

    with closing(get_connection(db_path)) as connection, connection:
        rows = connection.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def _count_rows(
    db_path: Path,
    clauses: list[str],
    params: list[Any],
) -> int:
    with closing(get_connection(db_path)) as connection, connection:
        row = connection.execute(
            "SELECT COUNT(*) AS count FROM live_events" + _where(clauses),
            params,
        ).fetchone()
    return int(row["count"])


def _severity_counts(
    db_path: Path,
    *,
    search: str | None,
    channel: str | None,
    provider: str | None,
    event_id: str | None,
    username: str | None,
    since_minutes: int | None,
    alerts_only: bool,
    severity: str | None = None,
    rule_id: str | None = None,
) -> dict[str, int]:
    clauses, params = _filters(
        severity,
        search,
        channel,
        provider,
        event_id,
        username,
        since_minutes,
        alerts_only,
        rule_id,
    )
    where = _where(clauses)
    counts = {"High": 0, "Medium": 0, "Low": 0}

    with closing(get_connection(db_path)) as connection, connection:
        rows = connection.execute(
            "SELECT severity, COUNT(*) AS count FROM live_events"
            + where
            + " GROUP BY severity",
            params,
        ).fetchall()

    for row in rows:
        if row["severity"] in counts:
            counts[str(row["severity"])] = int(row["count"])
    counts["Total"] = sum(counts.values())
    return counts


def _dimension_values(db_path: Path, column: str) -> list[str]:
    allowed = {"channel", "provider", "event_id", "username", "rule_id", "rule_name"}
    if column not in allowed:
        raise ValueError("Unsupported dimension")

    with closing(get_connection(db_path)) as connection, connection:
        rows = connection.execute(
            f"SELECT DISTINCT {column} AS value FROM live_events "
            f"WHERE {column} NOT IN ('', 'unknown') ORDER BY {column} LIMIT 150"
        ).fetchall()
    return [str(row["value"]) for row in rows]


def _top_values(
    db_path: Path,
    column: str,
    clauses: list[str],
    params: list[Any],
    limit: int = 7,
) -> list[dict[str, Any]]:
    if column not in {"provider", "event_id", "username", "channel", "rule_id", "rule_name"}:
        raise ValueError("Unsupported ranking field")

    with closing(get_connection(db_path)) as connection, connection:
        rows = connection.execute(
            f"SELECT {column} AS label, COUNT(*) AS count FROM live_events"
            + _where(clauses)
            + f" GROUP BY {column} ORDER BY count DESC, {column} LIMIT ?",
            [*params, limit],
        ).fetchall()
    return [
        {"label": str(row["label"]), "count": int(row["count"])}
        for row in rows
        if str(row["label"]).strip() not in {"", "unknown"}
    ]


def technique_counts(db_path: Path, clauses: list[str], params: list[Any]) -> list[dict[str, Any]]:
    """Count alerts per ATT&CK technique across the filtered events.

    A technique is stored as a comma-separated list on the alert, so the count
    is built here rather than in SQL. That keeps the query portable and makes
    the tag format a storage detail rather than a schema constraint.
    """

    with closing(get_connection(db_path)) as connection, connection:
        rows = connection.execute(
            "SELECT techniques FROM live_events"
            + _where([*clauses, "is_alert = 1", "techniques != ''"]),
            params,
        ).fetchall()

    counts: dict[str, int] = {}
    for row in rows:
        for technique in str(row["techniques"]).split(","):
            name = technique.strip()
            if name:
                counts[name] = counts.get(name, 0) + 1

    return [
        {"label": technique, "count": count}
        for technique, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:10]
    ]


def _timeline(
    db_path: Path,
    clauses: list[str],
    params: list[Any],
    points: int = 20,
) -> list[dict[str, Any]]:
    with closing(get_connection(db_path)) as connection, connection:
        rows = connection.execute(
            "SELECT substr(timestamp,1,16) AS bucket, COUNT(*) AS count "
            "FROM live_events"
            + _where(clauses)
            + " GROUP BY bucket ORDER BY bucket DESC LIMIT ?",
            [*params, points],
        ).fetchall()

    return [
        {"label": str(row["bucket"]), "count": int(row["count"])}
        for row in reversed(rows)
    ]


def dashboard_snapshot(
    db_path: Path,
    *,
    severity: str | None = None,
    search: str | None = None,
    channel: str | None = None,
    provider: str | None = None,
    event_id: str | None = None,
    username: str | None = None,
    since_minutes: int | None = None,
    alerts_only: bool = False,
    rule_id: str | None = None,
) -> dict[str, Any]:
    """Build one live dashboard response from current SQLite data."""

    events = query_events(
        db_path,
        severity=severity,
        search=search,
        channel=channel,
        provider=provider,
        event_id=event_id,
        username=username,
        since_minutes=since_minutes,
        alerts_only=alerts_only,
        rule_id=rule_id,
    )
    counts = _severity_counts(
        db_path,
        search=search,
        channel=channel,
        provider=provider,
        event_id=event_id,
        username=username,
        since_minutes=since_minutes,
        alerts_only=alerts_only,
        severity=severity,
        rule_id=rule_id,
    )
    filter_counts = _severity_counts(
        db_path,
        search=search,
        channel=channel,
        provider=provider,
        event_id=event_id,
        username=username,
        since_minutes=since_minutes,
        alerts_only=alerts_only,
    )

    clauses, params = _filters(
        severity,
        search,
        channel,
        provider,
        event_id,
        username,
        since_minutes,
        alerts_only,
        rule_id,
    )
    alert_clauses = [*clauses, "is_alert = 1"]
    alert_params = list(params)
    correlation_clauses = [*alert_clauses, "source = ?"]
    correlation_params = [*params, CORRELATION_SOURCE]

    recent_clauses, recent_params = _filters(
        severity, search, channel, provider, event_id, username, 1, alerts_only, rule_id
    )

    return {
        "counts": counts,
        "filter_counts": filter_counts,
        "alerts": query_events(
            db_path,
            severity=severity,
            search=search,
            channel=channel,
            provider=provider,
            event_id=event_id,
            username=username,
            since_minutes=since_minutes,
            alerts_only=True,
            rule_id=rule_id,
            limit=30,
        ),
        "correlations": query_events(
            db_path,
            severity=severity,
            search=search,
            channel="correlation",
            provider=provider,
            event_id=event_id,
            username=username,
            since_minutes=since_minutes,
            alerts_only=True,
            limit=20,
        ),
        "alert_count": _count_rows(db_path, alert_clauses, alert_params),
        "correlation_count": _count_rows(db_path, correlation_clauses, correlation_params),
        "events_per_minute": _count_rows(db_path, recent_clauses, recent_params),
        "events": events,
        "visible": len(events),
        "dimensions": {
            "channels": _dimension_values(db_path, "channel"),
            "providers": _dimension_values(db_path, "provider"),
            "event_ids": _dimension_values(db_path, "event_id"),
            "usernames": _dimension_values(db_path, "username"),
            "rules": _dimension_values(db_path, "rule_id"),
        },
        "top_providers": _top_values(db_path, "provider", clauses, params),
        "top_event_ids": _top_values(db_path, "event_id", clauses, params),
        "top_rules": _top_values(db_path, "rule_name", alert_clauses, alert_params),
        "top_techniques": technique_counts(db_path, clauses, params),
        "timeline": _timeline(db_path, clauses, params),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def system_metrics(db_path: Path) -> dict[str, Any]:
    """Measure the machine running the collector; report failures explicitly."""
    import socket

    try:
        import psutil

        return {
            "available": True,
            "host": socket.gethostname(),
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage(str(db_path.resolve().parent)).percent,
            "sampled_at": datetime.now(timezone.utc).isoformat(),
        }
    except (ImportError, OSError, RuntimeError) as exc:
        return {"available": False, "host": socket.gethostname(), "error": str(exc)}


def _bearer_token(request: Any) -> str:
    """Read a token from the Authorization header or a query parameter."""

    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    supplied = request.headers.get("X-Auth-Token", "").strip()
    if supplied:
        return supplied
    return (request.args.get("token") or "").strip()


def dashboard_app(
    db_path: Path,
    collector_status: dict[str, Any] | None = None,
    *,
    auth_token: str = "",
    notifier: Notifier | None = None,
    runtime: dict[str, Any] | None = None,
    secure_cookies: bool = False,
):
    """Create the Flask application.

    ``auth_token`` protects every route when it is set. Left empty, the console
    is open on localhost, which is the documented default for a lab.
    """

    try:
        from flask import Flask, jsonify, redirect, render_template, request
    except ImportError as exc:
        raise RuntimeError(
            "Flask is required to run the console, and it is not available here."
        ) from exc

    source_dir = Path(__file__).resolve().parent
    app = Flask(
        __name__,
        template_folder=str(source_dir / "templates"),
        static_folder=str(source_dir / "static"),
    )
    app.config["MAX_CONTENT_LENGTH"] = 3_000_000
    # Prepare WAL and schema before concurrent dashboard/ingestion requests arrive.
    get_connection(db_path).close()

    def authorised() -> bool:
        if not auth_token:
            return True
        return _bearer_token(request) == auth_token

    def refused():
        return jsonify({"error": "Authentication required. Send the token as a bearer token."}), 401

    # Routes that must work before anybody has signed in: the page itself, the
    # health probe, the identity probe the page uses to decide whether to show
    # the sign-in form, the form's own target, and agent ingestion, which
    # authenticates with a host key instead of a session.
    OPEN_PATHS = {"/", "/health", "/login", "/logout", "/api/me", "/api/ingest", "/api/setup"}

    # Whether accounts exist is asked once and then remembered, so the gate does
    # not query on every request. Creating the first user clears it.
    accounts = {"known": False, "required": False}

    def accounts_required() -> bool:
        if not accounts["known"]:
            with closing(get_connection(db_path)) as connection:
                accounts["required"] = bool(auth.list_users(connection))
            accounts["known"] = True
        return accounts["required"]

    def current_user():
        """The signed-in user, or None.

        The console is open until the first account is created, which is the
        documented lab default; after that every protected route needs a session.
        """
        token = request.cookies.get(SESSION_COOKIE, "")
        if not token:
            return None
        with closing(get_connection(db_path)) as connection:
            return auth.validate_session(connection, token)

    def operator():
        """The signed-in user, or the implicit local operator while the console is open.

        The console has no accounts until the first one is created, and the
        documented default is that it is then open on loopback. Without this,
        the account-related routes would answer 401 to everybody in that state
        and three panels would be dead on a console that is otherwise open.
        """

        user = current_user()
        if user is not None:
            return user
        if accounts_required():
            return None
        return {"username": "local", "role": "admin"}

    def require(action: str):
        """A refusal response when the signed-in user may not do this, else None."""

        user = operator()
        if user is None:
            return jsonify({"error": "Sign in to use this console."}), 401
        if not auth.has_permission(str(user["role"]), action):
            return (
                jsonify(
                    {
                        "error": (
                            f"Your role ({user['role']}) may not "
                            f"{action.replace('_', ' ')}."
                        )
                    }
                ),
                403,
            )
        return None

    def require_admin(what: str):
        """A refusal when the signed-in user is not an administrator.

        The permission matrix has no dedicated system action, so the operational
        routes - rebuilding an index or a baseline, taking a backup, clearing a
        lockout - ask for the administrator permission and name the action in
        the message, rather than reporting a permission the operator was never
        trying to use.
        """

        user = operator()
        if user is None:
            return jsonify({"error": "Sign in to use this console."}), 401
        if not auth.has_permission(str(user["role"]), "manage_users"):
            return jsonify({"error": f"Your role ({user['role']}) may not {what}."}), 403
        return None

    @app.before_request
    def require_token():
        # The page itself is served without the header; it carries the token in
        # the query string so its own fetches can present it.
        if request.path == "/" and request.method == "GET":
            return None
        if not authorised():
            return refused()
        if request.path in OPEN_PATHS:
            return None
        if not accounts_required():
            return None
        if current_user() is None:
            return jsonify({"error": "Sign in to use this console."}), 401
        return None

    @app.errorhandler(ValueError)
    def invalid_input(error):
        return jsonify({"error": str(error)}), 400

    @app.errorhandler(RecursionError)
    def excessively_nested(error):
        return jsonify({"error": "Event data is nested too deeply."}), 400

    @app.errorhandler(413)
    def too_large(error):
        return jsonify({"error": "Import file is too large. Keep it under 3 MB."}), 413

    @app.get("/")
    def index():
        if auth_token and (request.args.get("token") or "").strip() != auth_token:
            return (
                "<!doctype html><title>SIEM console</title>"
                "<p>This console requires a token. Append "
                "<code>?token=YOUR_TOKEN</code> to the address.</p>",
                401,
            )
        return render_template("dashboard.html", auth_token=auth_token)

    @app.get("/health")
    def health():
        return jsonify(
            {
                "status": "ok",
                "database": str(db_path),
                "rules": len(default_engine().rules),
                "correlation_rules": len(default_engine().correlations),
                "auth": bool(auth_token),
                "intel_indicators": default_intel().size,
            }
        )

    @app.get("/api/dashboard")
    def api_dashboard():
        since_text = request.args.get("since", "").strip()
        since_minutes = None
        if since_text:
            if not since_text.isascii() or not since_text.isdigit():
                return jsonify({"error": "since must be a whole number of minutes"}), 400
            since_minutes = int(since_text)
            if since_minutes > MAX_SINCE_MINUTES:
                return (
                    jsonify({"error": f"since is limited to {MAX_SINCE_MINUTES} minutes"}),
                    400,
                )
        snapshot = dashboard_snapshot(
            db_path,
            severity=request.args.get("severity") or None,
            search=request.args.get("search") or None,
            channel=request.args.get("channel") or None,
            provider=request.args.get("provider") or None,
            event_id=request.args.get("event_id") or None,
            username=request.args.get("username") or None,
            since_minutes=since_minutes,
            alerts_only=_as_bool(request.args.get("alerts")),
            rule_id=request.args.get("rule_id") or None,
        )
        snapshot["collector"] = collector_status or {
            "enabled": False,
            "running": False,
            "ingested": 0,
            "backfilled": 0,
            "channels": {},
            "last_error": "",
            "last_poll": "",
        }
        snapshot["system"] = system_metrics(db_path)
        snapshot["notifier"] = (
            notifier.status()
            if notifier is not None
            else {"enabled": False, "sent": 0, "failed": 0, "last_error": ""}
        )
        snapshot["runtime"] = runtime or {}
        return jsonify(snapshot)

    @app.get("/api/rules")
    def api_rules():
        engine = default_engine()
        return jsonify(
            {
                "detections": engine.coverage(),
                "correlations": engine.correlation_coverage(),
                "techniques": engine.attack_coverage(),
            }
        )

    @app.post("/api/correlate")
    def api_correlate():
        window = request.args.get("since", "120").strip()
        if not window.isascii() or not window.isdigit():
            return jsonify({"error": "since must be a whole number of minutes"}), 400
        raised = correlate(db_path, default_engine().correlations, since_minutes=int(window))
        return jsonify({"raised": raised}), 201

    @app.post("/api/pcap")
    def api_pcap():
        from .pcap_ingest import PcapError, ingest_capture

        uploaded = request.files.get("file")
        if uploaded is None or not uploaded.filename:
            return jsonify({"error": "Choose a .pcap or .pcapng capture to import."}), 400

        suffix = Path(uploaded.filename).suffix.lower()
        if suffix not in {".pcap", ".pcapng", ".cap"}:
            return jsonify({"error": "Supported captures: .pcap, .pcapng, and .cap"}), 400

        scratch = Path(db_path).resolve().parent / "captures"
        scratch.mkdir(parents=True, exist_ok=True)
        target = scratch / Path(uploaded.filename).name
        target.write_bytes(uploaded.read())

        try:
            summary = ingest_capture(db_path, target)
        except (PcapError, ValueError, OSError) as exc:
            return jsonify({"error": str(exc)}), 400

        summary["correlations_raised"] = correlate(
            db_path, default_engine().correlations, since_minutes=1440
        )
        return jsonify(summary), 201

    @app.post("/api/events")
    def api_events():
        data = request.get_json(silent=True)
        if isinstance(data, dict):
            payloads = [data]
        elif isinstance(data, list) and all(isinstance(item, dict) for item in data):
            payloads = data
        else:
            return jsonify({"error": "Send one event object or a list of event objects."}), 400

        try:
            inserted = ingest_payloads(db_path, payloads, "api", notifier=notifier)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"inserted": inserted}), 201

    @app.post("/api/import")
    def api_import():
        uploaded = request.files.get("file")
        if uploaded is None or not uploaded.filename:
            return jsonify({"error": "Choose a JSON, JSONL, NDJSON, or CSV file."}), 400

        try:
            payloads = parse_event_file(uploaded.filename, uploaded.read())
            inserted = ingest_payloads(
                db_path,
                payloads,
                f"import:{uploaded.filename}",
                notifier=notifier,
            )
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"inserted": inserted}), 201

    @app.post("/api/events/clear")
    def api_clear():
        reset_events(db_path)
        return jsonify({"cleared": True})

    # ---------------------------------------------------------------- identity

    @app.get("/api/me")
    def api_me():
        # Uses the same identity the rest of the console does. Answering 401 here
        # while the console is open made the page show a sign-in form for an
        # account that does not exist and cannot be created from the form.
        user = operator()
        if user is None:
            return jsonify({"error": "Not signed in."}), 401
        return jsonify({"username": user["username"], "role": user["role"]})

    @app.post("/login")
    def login():
        data = request.form if request.form else (request.get_json(silent=True) or {})
        if not isinstance(data, dict):
            data = {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        code = str(data.get("code", "")).strip()
        source_ip = request.remote_addr or ""
        with closing(get_connection(db_path)) as connection:
            # Refused before the password is even checked, so a locked account
            # cannot be used as an oracle for guessing.
            locked = security.is_locked_out(connection, username, source_ip)
            if locked["locked"]:
                connection.commit()
                return (
                    jsonify(
                        {
                            "error": (
                                "Too many failed attempts. Try again in "
                                f"{locked['remaining_seconds']} seconds."
                            ),
                            "locked": True,
                        }
                    ),
                    429,
                )

            user = auth.authenticate(connection, username, password)
            if user is None:
                security.record_failure(connection, username, source_ip)
                connection.commit()  # the failed attempt is an audit row
                return jsonify({"error": "Invalid username or password."}), 401

            # A second factor is only demanded once the account has confirmed
            # one; an unconfirmed enrolment is not yet a lock on the account.
            state = security.mfa_status(connection, user["username"])
            if state["enabled"]:
                if not code:
                    connection.commit()
                    return (
                        jsonify(
                            {
                                "error": "Enter the code from your authenticator app.",
                                "mfa_required": True,
                            }
                        ),
                        401,
                    )
                checked = security.verify_login_code(connection, user["username"], code)
                if not checked.get("valid"):
                    security.record_failure(connection, username, source_ip)
                    connection.commit()
                    return (
                        jsonify(
                            {"error": "That code was not accepted.", "mfa_required": True}
                        ),
                        401,
                    )

            security.record_success(connection, username, source_ip)
            session = auth.create_session(connection, user["username"], actor=user["username"])
            connection.commit()
        response = redirect("/")
        response.set_cookie(
            SESSION_COOKIE,
            session["token"],
            httponly=True,
            samesite="Lax",
            # Only asserted over HTTPS, because a Secure cookie that can never be
            # sent over plain HTTP would lock the operator out of their own lab.
            secure=secure_cookies,
        )
        return response

    @app.post("/logout")
    def logout():
        token = request.cookies.get(SESSION_COOKIE, "")
        if token:
            with closing(get_connection(db_path)) as connection:
                auth.revoke_session(connection, token)
                connection.commit()
        response = redirect("/")
        response.delete_cookie(SESSION_COOKIE)
        return response

    # ------------------------------------------------------------------ agents

    def host_by_name(connection, name: str):
        """The registry row for a host name, or None."""

        return next(
            (row for row in hosts.list_hosts(connection) if row["name"] == name), None
        )

    @app.post("/api/ingest")
    def api_ingest():
        """Accept a batch from a collector agent, authenticated by host key.

        The body is the contract documented in ``agent.py``:
        ``{"host_id", "agent_version", "platform", "events"}``, and the reply is
        ``{"accepted", "rejected", "errors"}``. A host that is unknown, disabled
        or presenting the wrong key is refused before anything is stored.
        """

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Send one JSON object."}), 400
        name = str(data.get("host_id", "")).strip()
        events = data.get("events")
        if not name:
            return jsonify({"error": "host_id is required."}), 400
        if not isinstance(events, list):
            return jsonify({"error": "events must be a list."}), 400

        key = _bearer_token(request)
        with closing(get_connection(db_path)) as connection:
            row = host_by_name(connection, name)
            if row is None or not hosts.verify_host_key(connection, int(row["host_id"]), key):
                # The same reply either way, so the endpoint does not confirm
                # which host names exist to somebody guessing.
                return jsonify({"error": "Unknown host or invalid key."}), 401
            if not row["enabled"]:
                return jsonify({"error": "This host is disabled."}), 403
            registry_id = int(row["host_id"])
            if data.get("agent_version") or data.get("platform"):
                connection.execute(
                    "UPDATE hosts SET agent_version = COALESCE(NULLIF(?, ''), agent_version), "
                    "platform = COALESCE(NULLIF(?, ''), platform) WHERE host_id = ?",
                    (
                        str(data.get("agent_version", "")),
                        str(data.get("platform", "")),
                        registry_id,
                    ),
                )
            connection.commit()

        errors: list[str] = []
        payloads: list[dict[str, Any]] = []
        for index, raw in enumerate(events):
            if not isinstance(raw, dict):
                errors.append(f"event {index}: not an object")
                continue
            try:
                event = schema.normalise_event(raw)
            except ValueError as exc:
                errors.append(f"event {index}: {exc}")
                continue
            payload = schema.to_payload(event, source_default="agent")
            payload["host"] = name
            payload["host_id"] = str(registry_id)
            payloads.append(payload)

        if payloads:
            try:
                ingest_payloads(db_path, payloads, f"agent:{name}", notifier=notifier)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            with closing(get_connection(db_path)) as connection:
                hosts.touch_host(connection, registry_id, len(payloads))
                connection.commit()

        return jsonify({"accepted": len(payloads), "rejected": len(errors), "errors": errors}), 202

    @app.get("/api/hosts")
    def api_hosts():
        with closing(get_connection(db_path)) as connection:
            rows = hosts.list_hosts(connection)
            summary = hosts.host_summary(connection)
        return jsonify({"hosts": rows, "summary": summary})

    @app.post("/api/hosts")
    def api_enrol_host():
        denied = require("manage_users")
        if denied:
            return denied
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"error": "Send one JSON object."}), 400
        name = str(data.get("name", "")).strip()
        if not name:
            return jsonify({"error": "name is required."}), 400
        user = operator()
        with closing(get_connection(db_path)) as connection:
            if host_by_name(connection, name) is not None:
                return jsonify({"error": f"A host called {name} is already enrolled."}), 400
            enrolled = hosts.enrol_host(
                connection,
                name,
                platform=str(data.get("platform", "")).strip() or None,
                agent_version=str(data.get("agent_version", "")).strip() or None,
            )
            auth.record_audit(
                connection,
                str(user["username"]),
                "enrol_host",
                name,
                f"host_id={enrolled['host_id']}",
            )
            connection.commit()
        return jsonify(enrolled), 201

    # ------------------------------------------------------------------ triage

    def detection_by_id(connection, detection_id: int):
        row = connection.execute(
            "SELECT * FROM live_events WHERE id = ? AND is_alert = 1", (detection_id,)
        ).fetchone()
        return dict(row) if row is not None else None

    def detection_payload(connection, row: dict[str, Any]) -> dict[str, Any]:
        """Shape a stored detection for the dashboard.

        The triage tables identify a detection's host by its name, which is what
        the queue filters on, so ``host_id`` in this payload is that name.
        """

        return {
            "id": int(row["id"]),
            "host_id": str(row.get("host", "")),
            "host": str(row.get("host", "")),
            "rule_id": str(row.get("rule_id", "")),
            "title": str(row.get("rule_name") or row.get("rule_id") or ""),
            "severity": str(row.get("severity", "")),
            "technique": str(row.get("techniques", "")),
            "timestamp": str(row.get("timestamp", "")),
            "status": str(row.get("status", "new")),
            "assignee": str(row.get("assignee", "")),
            "note_count": len(triage.list_notes(connection, row)),
        }

    @app.get("/api/detections")
    def api_detections():
        with closing(get_connection(db_path)) as connection:
            result = triage.list_detections(
                connection,
                status=request.args.get("status") or None,
                host_id=request.args.get("host_id") or None,
                assignee=request.args.get("assignee") or None,
                limit=_whole_number(request.args.get("limit"), 50),
                offset=_whole_number(request.args.get("offset"), 0),
            )
            summary = triage.triage_summary(connection)
            detections = [detection_payload(connection, row) for row in result["detections"]]
        return jsonify(
            {"detections": detections, "summary": summary, "total": result["total"]}
        )

    @app.post("/api/detections/<int:detection_id>/status")
    def api_detection_status(detection_id: int):
        denied = require("triage_detection")
        if denied:
            return denied
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"error": "Send one JSON object."}), 400
        user = operator()
        with closing(get_connection(db_path)) as connection:
            detection = detection_by_id(connection, detection_id)
            if detection is None:
                return jsonify({"error": "No such detection."}), 404
            updated = triage.set_status(
                connection,
                detection,
                str(data.get("status", "")),
                str(user["username"]),
                assignee=(str(data["assignee"]).strip() or None)
                if data.get("assignee") is not None
                else None,
            )
            connection.commit()
        return jsonify({"ok": True, "status": updated.get("status", "")})

    @app.get("/api/detections/<int:detection_id>/notes")
    def api_detection_notes(detection_id: int):
        with closing(get_connection(db_path)) as connection:
            detection = detection_by_id(connection, detection_id)
            if detection is None:
                return jsonify({"error": "No such detection."}), 404
            notes = triage.list_notes(connection, detection)
        return jsonify({"notes": notes})

    @app.post("/api/detections/<int:detection_id>/notes")
    def api_add_detection_note(detection_id: int):
        denied = require("triage_detection")
        if denied:
            return denied
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"error": "Send one JSON object."}), 400
        user = operator()
        with closing(get_connection(db_path)) as connection:
            detection = detection_by_id(connection, detection_id)
            if detection is None:
                return jsonify({"error": "No such detection."}), 404
            note = triage.add_note(
                connection, detection, str(user["username"]), str(data.get("text", ""))
            )
            connection.commit()
        return jsonify({"ok": True, "note": note}), 201

    # ------------------------------------------------------------- suppressions

    def suppression_payload(row: dict[str, Any]) -> dict[str, Any]:
        payload = dict(row)
        payload["created_by"] = str(row.get("actor", ""))
        return payload

    @app.get("/api/suppressions")
    def api_suppressions():
        denied = require("view_events")
        if denied:
            return denied
        with closing(get_connection(db_path)) as connection:
            rows = triage.list_suppressions(connection)
        return jsonify({"suppressions": [suppression_payload(row) for row in rows]})

    @app.post("/api/suppressions")
    def api_suppress():
        denied = require("manage_suppressions")
        if denied:
            return denied
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"error": "Send one JSON object."}), 400
        user = operator()
        expires = data.get("expires_days")
        try:
            expires_days = int(expires) if expires not in (None, "") else None
        except (TypeError, ValueError):
            return jsonify({"error": "expires_days must be a whole number of days."}), 400
        with closing(get_connection(db_path)) as connection:
            created = triage.suppress(
                connection,
                str(data.get("rule_id", "")).strip(),
                host_id=(str(data["host_id"]).strip() or None)
                if data.get("host_id") is not None
                else None,
                scope=str(data.get("scope", "host")).strip() or "host",
                reason=(str(data["reason"]).strip() or None)
                if data.get("reason") is not None
                else None,
                actor=str(user["username"]),
                expires_days=expires_days,
            )
            auth.record_audit(
                connection,
                str(user["username"]),
                "suppress_rule",
                str(created.get("rule_id", "")),
                f"scope={created.get('scope', '')} host={created.get('host_id', '')}",
            )
            connection.commit()
        return jsonify({"ok": True, "suppression": created}), 201

    @app.delete("/api/suppressions/<int:suppression_id>")
    def api_unsuppress(suppression_id: int):
        denied = require("manage_suppressions")
        if denied:
            return denied
        user = operator()
        with closing(get_connection(db_path)) as connection:
            removed = triage.unsuppress(connection, suppression_id, str(user["username"]))
            auth.record_audit(
                connection,
                str(user["username"]),
                "unsuppress_rule",
                str(removed.get("rule_id", "")),
                f"suppression_id={suppression_id}",
            )
            connection.commit()
        return jsonify({"ok": True, "suppression": removed})

    # ------------------------------------------------------------------- audit

    @app.get("/api/audit")
    def api_audit():
        denied = require("view_audit")
        if denied:
            return denied
        limit = _whole_number(request.args.get("limit"), 100)
        offset = _whole_number(request.args.get("offset"), 0)
        with closing(get_connection(db_path)) as connection:
            entries = auth.list_audit(connection, limit, offset)
            total = connection.execute(
                "SELECT COUNT(*) AS count FROM audit_log"
            ).fetchone()["count"]
        return jsonify({"entries": entries, "total": int(total)})

    @app.get("/api/schema")
    def api_schema():
        """The event schema this console stores, so the page can document itself."""

        return jsonify(schema.describe_schema())

    # --------------------------------------------------------------- first run

    @app.get("/api/setup")
    def api_setup():
        """Whether this console still needs its first account."""

        with closing(get_connection(db_path)) as connection:
            existing = auth.list_users(connection)
        return jsonify({"required": not existing, "accounts": len(existing)})

    @app.post("/api/setup")
    def api_setup_create():
        """Create the first administrator and sign them straight in.

        Refused once any account exists, so this is a first-run door and not a
        way to mint yourself another account; after the first, accounts are
        created by an administrator.
        """

        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"error": "Send one JSON object."}), 400
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        with closing(get_connection(db_path)) as connection:
            if auth.list_users(connection):
                return (
                    jsonify(
                        {
                            "error": (
                                "This console already has accounts. Ask an "
                                "administrator to create yours."
                            )
                        }
                    ),
                    409,
                )
            try:
                user = auth.create_user(
                    connection, username, password, "admin", actor="first-run"
                )
            except ValueError as exc:
                connection.commit()  # the refusal is an audit row
                return jsonify({"error": str(exc)}), 400
            session = auth.create_session(
                connection, user["username"], actor=user["username"]
            )
            connection.commit()

        # From here the console is locked, and the reply carries the session it
        # just issued so the operator lands signed in rather than at a form.
        accounts["known"] = True
        accounts["required"] = True
        response = jsonify({"ok": True, "username": user["username"], "role": user["role"]})
        response.set_cookie(
            SESSION_COOKIE,
            session["token"],
            httponly=True,
            samesite="Lax",
            secure=secure_cookies,
        )
        return response, 201

    # ------------------------------------------------------------------ search

    @app.get("/api/search/summary")
    def api_search_summary():
        with closing(get_connection(db_path)) as connection:
            summary = search.search_summary(connection)
        return jsonify(
            {
                "fts5": bool(summary["fts5_available"]),
                "indexed": bool(summary["index_exists"]),
                "indexed_events": int(summary["indexed_events"]),
                "events_total": int(summary.get("events_total", 0)),
                "index_behind": bool(summary.get("index_behind", False)),
            }
        )

    @app.get("/api/search")
    def api_search():
        with closing(get_connection(db_path)) as connection:
            result = search.search_events(
                connection,
                request.args.get("q", ""),
                limit=_whole_number(request.args.get("limit"), 50),
                offset=_whole_number(request.args.get("offset"), 0),
            )
        return jsonify(result)

    @app.post("/api/search/rebuild")
    def api_search_rebuild():
        denied = require_admin("rebuild the search index")
        if denied:
            return denied
        with closing(get_connection(db_path)) as connection:
            result = search.rebuild_index(connection)
            connection.commit()
        return jsonify({"ok": True, "processed": int(result.get("rows_processed", 0))})

    # ---------------------------------------------------------------- baseline

    @app.get("/api/baseline")
    def api_baseline():
        with closing(get_connection(db_path)) as connection:
            rows = baseline.list_baselines(
                connection,
                host=request.args.get("host") or None,
                kind=request.args.get("kind") or None,
            )
            summary = baseline.baseline_summary(connection)
        # The page names the column `samples`; the module calls it sample_count.
        for row in rows:
            row["samples"] = row.get("sample_count", 0)
        return jsonify(
            {
                "baselines": rows,
                "summary": {
                    "keys": int(summary["baselined"]),
                    "hosts": int(summary["hosts"]),
                    "insufficient": int(summary["insufficient_history"]),
                    "min_samples": int(summary["min_samples"]),
                    "window_hours": int(summary["window_hours"]),
                },
            }
        )

    @app.get("/api/baseline/deviations")
    def api_baseline_deviations():
        with closing(get_connection(db_path)) as connection:
            rows = baseline.detect_deviations(
                connection,
                window_minutes=_whole_number(request.args.get("window_minutes"), 60),
                sigma=float(request.args.get("sigma", 3.0) or 3.0),
            )
        for row in rows:
            row["sigma"] = row.get("sigma_distance")
        return jsonify({"deviations": rows, "total": len(rows)})

    @app.post("/api/baseline/build")
    def api_baseline_build():
        denied = require_admin("rebuild the baseline")
        if denied:
            return denied
        with closing(get_connection(db_path)) as connection:
            result = baseline.build_baseline(
                connection,
                hours=_whole_number(request.args.get("hours"), 168),
            )
            connection.commit()
        return jsonify(
            {
                "ok": True,
                "keys": int(result.get("built", 0)),
                "skipped": int(result.get("skipped", 0)),
            }
        )

    # ---------------------------------------------------------------- security

    @app.get("/api/security")
    def api_security():
        user = operator()
        if user is None:
            return jsonify({"error": "Sign in to use this console."}), 401
        with closing(get_connection(db_path)) as connection:
            summary = security.lockout_summary(connection)
            mine = security.mfa_status(connection, str(user["username"]))
        lockouts = [
            {
                "username": str(row.get("username", "")),
                "source_ip": str(row.get("source_ip", "")),
                "failures": int(row.get("failure_count", row.get("failures", 0)) or 0),
                "locked_until": str(row.get("locked_until", "") or ""),
            }
            for row in summary.get("active_lockouts", [])
        ]
        recent = [
            {
                "username": str(row.get("username", "")),
                "source_ip": str(row.get("source_ip", "")),
                "failures": int(row.get("failure_count", row.get("failures", 0)) or 0),
                "window_seconds": int(summary.get("window_seconds", 0)),
            }
            for row in summary.get("recent_failures", [])
        ]
        return jsonify(
            {
                "lockouts": lockouts,
                "recent_failures": recent,
                "mfa_enabled": bool(mine["enabled"]),
            }
        )

    @app.post("/api/security/lockout/clear")
    def api_lockout_clear():
        denied = require_admin("clear a lockout")
        if denied:
            return denied
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"error": "Send one JSON object."}), 400
        user = operator()
        username = str(data.get("username", "")).strip() or None
        source_ip = str(data.get("source_ip", "")).strip() or None
        if username is None and source_ip is None:
            return jsonify({"error": "Give a username, a source address, or both."}), 400
        with closing(get_connection(db_path)) as connection:
            cleared = security.clear_lockout(
                connection, username=username, source_ip=source_ip, actor=str(user["username"])
            )
            connection.commit()
        return jsonify({"ok": True, "cleared": cleared})

    # -------------------------------------------------------------------- mfa

    def own_username() -> str:
        return str(operator()["username"])

    @app.get("/api/mfa")
    def api_mfa():
        user = operator()
        if user is None:
            return jsonify({"error": "Sign in to use this console."}), 401
        with closing(get_connection(db_path)) as connection:
            state = security.mfa_status(connection, str(user["username"]))
        return jsonify(
            {
                "enabled": bool(state["enabled"]),
                "confirmed": bool(state["enabled"]),
                "pending": bool(state["pending"]),
                "recovery_codes_remaining": int(state["recovery_codes_remaining"]),
            }
        )

    @app.post("/api/mfa/setup")
    def api_mfa_setup():
        user = operator()
        if user is None:
            return jsonify({"error": "Sign in to use this console."}), 401
        with closing(get_connection(db_path)) as connection:
            started = security.start_enrolment(connection, str(user["username"]))
            connection.commit()
        # The secret and the recovery codes are returned exactly once, here.
        return jsonify(
            {
                "secret": started["secret"],
                "uri": started["provisioning_uri"],
                "recovery_codes": started["recovery_codes"],
            }
        )

    @app.post("/api/mfa/confirm")
    def api_mfa_confirm():
        user = operator()
        if user is None:
            return jsonify({"error": "Sign in to use this console."}), 401
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"error": "Send one JSON object."}), 400
        with closing(get_connection(db_path)) as connection:
            try:
                state = security.confirm_enrolment(
                    connection, str(user["username"]), str(data.get("code", ""))
                )
            except ValueError as exc:
                connection.commit()
                return jsonify({"error": str(exc)}), 400
            connection.commit()
        return jsonify({"ok": True, "enabled": bool(state["enabled"])})

    @app.post("/api/mfa/disable")
    def api_mfa_disable():
        user = operator()
        if user is None:
            return jsonify({"error": "Sign in to use this console."}), 401
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"error": "Send one JSON object."}), 400
        password = str(data.get("password", ""))
        with closing(get_connection(db_path)) as connection:
            # Turning a second factor off is a security downgrade, so it costs
            # the password rather than just the session.
            if auth.authenticate(connection, str(user["username"]), password) is None:
                connection.commit()
                return jsonify({"error": "That password was not accepted."}), 401
            security.disable_mfa(connection, str(user["username"]), actor=str(user["username"]))
            connection.commit()
        return jsonify({"ok": True})

    # ----------------------------------------------------------------- backups

    @app.get("/api/backups")
    def api_backups():
        user = operator()
        if user is None:
            return jsonify({"error": "Sign in to use this console."}), 401
        folder = backup_directory(db_path)
        rows = [
            {"path": str(row["path"]), "bytes": int(row["size_bytes"]), "created_at": str(row["created_at"])}
            for row in backup.list_backups(folder)
        ]
        summary = backup.backup_summary(folder)
        return jsonify(
            {
                "backups": rows,
                "summary": {
                    "count": int(summary["count"]),
                    "total_bytes": int(summary["total_bytes"]),
                    "newest_age_seconds": summary["newest_age_seconds"],
                },
                "directory": str(folder),
            }
        )

    @app.post("/api/backups")
    def api_backup_create():
        denied = require_admin("create a backup")
        if denied:
            return denied
        user = operator()
        with closing(get_connection(db_path)) as connection:
            auth.record_audit(
                connection, str(user["username"]), "backup_create", str(db_path), None
            )
            connection.commit()
        created = backup.create_backup(db_path, backup_directory(db_path), label="manual")
        return jsonify({"ok": True, "path": str(created["path"]), "bytes": int(created["size_bytes"])}), 201

    @app.post("/api/backups/verify")
    def api_backup_verify():
        denied = require_admin("verify a backup")
        if denied:
            return denied
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"error": "Send one JSON object."}), 400
        path = str(data.get("path", "")).strip()
        if not path:
            return jsonify({"error": "path is required."}), 400
        folder = backup_directory(db_path)
        # Only files this console wrote may be inspected, so the route cannot be
        # pointed at an arbitrary path on the machine.
        try:
            inside = Path(path).resolve().parent == Path(folder).resolve()
        except OSError:
            inside = False
        if not inside:
            return jsonify({"error": "That is not a backup written by this console."}), 400
        result = backup.verify_backup(path)
        tables = result.get("tables") or {}
        return jsonify(
            {
                "ok": bool(result["ok"]),
                "integrity": str(result.get("integrity", "")),
                "tables": len(tables),
                "events": int(tables.get("live_events", 0)),
                "error": result.get("error"),
            }
        )

    return app


def _correlation_worker(
    db_path: Path,
    interval: float,
    stop_event: threading.Event,
    status: dict[str, Any],
) -> None:
    """Raise correlation alerts on a timer, independently of ingestion."""

    while not stop_event.is_set():
        try:
            raised = correlate(db_path, default_engine().correlations, since_minutes=240)
            status["raised"] = status.get("raised", 0) + raised
            status["last_run"] = datetime.now(timezone.utc).isoformat()
            status["last_error"] = ""
        except (sqlite3.Error, RuleError, ValueError, OSError) as exc:
            status["last_error"] = str(exc)
        stop_event.wait(interval)


def _retention_worker(
    db_path: Path,
    retain_days: int,
    max_db_mb: int,
    interval: float,
    stop_event: threading.Event,
    status: dict[str, Any],
) -> None:
    """Prune the store on a timer so it does not grow without limit."""

    while not stop_event.is_set():
        try:
            removed = prune_events(db_path, retain_days)
            removed += prune_to_size(db_path, max_db_mb)
            status["removed"] = status.get("removed", 0) + removed
            status["size_mb"] = database_size_mb(db_path)
            status["max_db_mb"] = max_db_mb
            status["last_run"] = datetime.now(timezone.utc).isoformat()
            status["last_error"] = ""
        except (sqlite3.Error, OSError) as exc:
            status["last_error"] = str(exc)
        stop_event.wait(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the live MKMK SIEM console.")
    parser.add_argument("--db", type=Path, default=Path("siem_live.db"))
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument(
        "--no-windows-events",
        action="store_true",
        help="Run without the Windows Event Log collector.",
    )
    parser.add_argument(
        "--intel-db",
        type=Path,
        default=None,
        help="Threat-intelligence store written by the aggregator project.",
    )
    parser.add_argument(
        "--retain-days",
        type=int,
        default=DEFAULT_RETAIN_DAYS,
        help=f"Delete events older than this many days (0 disables). Default {DEFAULT_RETAIN_DAYS}.",
    )
    parser.add_argument(
        "--max-db-mb",
        type=int,
        default=DEFAULT_MAX_DB_MB,
        help=(
            "Delete the oldest events once the store passes this size (0 disables). "
            f"Default {DEFAULT_MAX_DB_MB}."
        ),
    )
    parser.add_argument(
        "--alert-webhook",
        default=os.environ.get("SIEM_ALERT_WEBHOOK", ""),
        help="POST new alerts to this URL.",
    )
    parser.add_argument(
        "--alert-log",
        type=Path,
        default=None,
        help="Append new alerts to this file as JSON lines.",
    )
    parser.add_argument(
        "--alert-min-severity",
        choices=VALID_SEVERITIES,
        default="Medium",
        help="Lowest severity that is delivered. Default Medium.",
    )
    parser.add_argument(
        "--auth-token",
        default=os.environ.get("SIEM_AUTH_TOKEN", ""),
        help="Require this token on every route. Empty leaves the console open on localhost.",
    )
    parser.add_argument(
        "--tls-cert",
        type=Path,
        default=None,
        help="Serve HTTPS with this certificate. Needs --tls-key as well.",
    )
    parser.add_argument(
        "--tls-key",
        type=Path,
        default=None,
        help="The private key for --tls-cert.",
    )
    parser.add_argument(
        "--correlate-seconds",
        type=float,
        default=20.0,
        help="How often to look for sequences across stored alerts.",
    )
    args = parser.parse_args()

    get_connection(args.db).close()
    if args.reset:
        reset_events(args.db)
        print("Cleared the live event store.")

    set_intel(ThreatIntel.load(args.intel_db))
    notifier = Notifier(
        webhook=args.alert_webhook,
        log_path=args.alert_log,
        min_severity=args.alert_min_severity,
    )

    stop_event = threading.Event()
    correlation_status: dict[str, Any] = {"raised": 0, "last_run": "", "last_error": ""}
    retention_status: dict[str, Any] = {"removed": 0, "last_run": "", "last_error": ""}

    threads: list[threading.Thread] = []
    if args.correlate_seconds > 0:
        threads.append(
            threading.Thread(
                target=_correlation_worker,
                args=(args.db, args.correlate_seconds, stop_event, correlation_status),
                name="correlation",
                daemon=True,
            )
        )
    if args.retain_days > 0 or args.max_db_mb > 0:
        threads.append(
            threading.Thread(
                target=_retention_worker,
                args=(args.db, args.retain_days, args.max_db_mb, 900.0, stop_event, retention_status),
                name="retention",
                daemon=True,
            )
        )
    for thread in threads:
        thread.start()

    collector = WindowsEventCollector(
        args.db,
        ingest_payloads,
        notifier=notifier,
    )
    if not args.no_windows_events:
        collector.start()

    retention_status["size_mb"] = database_size_mb(args.db)
    retention_status["max_db_mb"] = args.max_db_mb
    runtime = {
        "retain_days": args.retain_days,
        "max_db_mb": args.max_db_mb,
        "size_mb": database_size_mb(args.db),
        "correlation": correlation_status,
        "retention": retention_status,
        "rules": len(default_engine().rules),
        "correlation_rules": len(default_engine().correlations),
        "intel_indicators": default_intel().size,
        "auth_enabled": bool(args.auth_token),
    }

    try:
        print(f"SIEM database: {args.db}")
        print(
            f"Rules: {runtime['rules']} detections, "
            f"{runtime['correlation_rules']} correlation rules, "
            f"{runtime['intel_indicators']} threat indicators"
        )
        if not args.auth_token:
            print("Authentication is off. This console is for a local lab.")
        try:
            tls = tls_context(args.tls_cert, args.tls_key)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        if tls is None:
            print("Serving plain HTTP. Pass --tls-cert and --tls-key to serve HTTPS.")
        else:
            print(f"HTTPS is on, using {args.tls_cert}.")
        dashboard_app(
            args.db,
            collector.status,
            auth_token=args.auth_token,
            notifier=notifier,
            runtime=runtime,
            secure_cookies=tls is not None,
        ).run(
            host=args.host,
            port=args.port,
            debug=False,
            threaded=True,
            ssl_context=tls,
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    finally:
        collector.stop()
        stop_event.set()
        for thread in threads:
            thread.join(timeout=2)


if __name__ == "__main__":
    main()
