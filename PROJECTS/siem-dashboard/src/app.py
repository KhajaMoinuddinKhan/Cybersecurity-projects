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
import threading
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .correlation import CORRELATION_SOURCE, correlate
from .enrichment import ThreatIntel, apply_enrichment
from .notify import Notifier
from .rules import RuleEngine, RuleError, shared_engine
from .windows_collector import WindowsEventCollector

VALID_SEVERITIES = ("High", "Medium", "Low")

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
    )


INSERT_SQL = """INSERT OR IGNORE INTO live_events(
    timestamp,channel,provider,event_id,level,severity,username,host,
    source_ip,message,record_id,source,is_alert,rule_name,raw_log,external_id,
    rule_id,techniques,matched_on,enrichment
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""


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
        before = connection.total_changes
        connection.executemany(INSERT_SQL, rows)
        inserted = connection.total_changes - before

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
        before = connection.total_changes
        connection.execute(
            "DELETE FROM live_events WHERE datetime(timestamp) < datetime(?)",
            (cutoff,),
        )
        return connection.total_changes - before


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
):
    """Create the Flask application.

    ``auth_token`` protects every route when it is set. Left empty, the console
    is open on localhost, which is the documented default for a lab.
    """

    try:
        from flask import Flask, jsonify, render_template, request
    except ImportError as exc:
        raise RuntimeError(
            "Flask is required. Run: python -m pip install -r requirements.txt"
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

    @app.before_request
    def require_token():
        # The page itself is served without the header; it carries the token in
        # the query string so its own fetches can present it.
        if request.path == "/" and request.method == "GET":
            return None
        if authorised():
            return None
        return refused()

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
        dashboard_app(
            args.db,
            collector.status,
            auth_token=args.auth_token,
            notifier=notifier,
            runtime=runtime,
        ).run(host=args.host, port=args.port, debug=False, threaded=True)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    finally:
        collector.stop()
        stop_event.set()
        for thread in threads:
            thread.join(timeout=2)


if __name__ == "__main__":
    main()
