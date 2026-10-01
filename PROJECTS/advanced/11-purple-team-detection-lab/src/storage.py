"""Durable SQLite storage for events, alerts, and threat indicators."""
from __future__ import annotations
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from .models import Alert, SecurityEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
 timestamp TEXT NOT NULL, event_type TEXT NOT NULL, source TEXT NOT NULL,
 username TEXT NOT NULL, host TEXT NOT NULL, data TEXT NOT NULL, received_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_events_timestamp ON events(timestamp);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, alert_key TEXT NOT NULL UNIQUE,
 rule_id TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL,
 severity TEXT NOT NULL, technique_id TEXT NOT NULL, technique_name TEXT NOT NULL,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, group_value TEXT NOT NULL,
 event_ids TEXT NOT NULL, host TEXT NOT NULL, username TEXT NOT NULL,
 source TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_alerts_created_at ON alerts(created_at);
CREATE TABLE IF NOT EXISTS iocs (
 type TEXT NOT NULL, value TEXT NOT NULL, source TEXT NOT NULL,
 imported_at TEXT NOT NULL, PRIMARY KEY(type,value));
"""


def get_connection(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript(SCHEMA)
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(alerts)")}
    if "alert_key" not in columns:
        connection.execute("ALTER TABLE alerts ADD COLUMN alert_key TEXT")
        connection.execute("UPDATE alerts SET alert_key = 'legacy-' || id WHERE alert_key IS NULL")
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_alerts_key ON alerts(alert_key)")
    if "created_at" not in columns:
        connection.execute("ALTER TABLE alerts ADD COLUMN created_at TEXT")
        connection.execute("UPDATE alerts SET created_at = COALESCE(first_seen, datetime('now')) WHERE created_at IS NULL")
    connection.commit()
    return connection


def append_events(path: Path, events: Iterable[SecurityEvent]) -> int:
    now = datetime.now(timezone.utc).isoformat()
    rows = [(e.event_id, e.timestamp.isoformat(), e.event_type, e.source, e.user, e.host,
             json.dumps(e.data, ensure_ascii=False, sort_keys=True), now) for e in events]
    if not rows: return 0
    with closing(get_connection(path)) as connection, connection:
        before = connection.total_changes
        connection.executemany("INSERT OR IGNORE INTO events(event_id,timestamp,event_type,source,username,host,data,received_at) VALUES(?,?,?,?,?,?,?,?)", rows)
        return connection.total_changes - before


def list_events(path: Path, limit: int = 500) -> list[dict[str, Any]]:
    with closing(get_connection(path)) as connection:
        rows = connection.execute("SELECT * FROM events ORDER BY datetime(timestamp) DESC,id DESC LIMIT ?", (max(1, min(limit, 5000)),)).fetchall()
    return [dict(row) | {"data": json.loads(row["data"])} for row in rows]


def _alert_key(alert: Alert) -> str:
    return f"{alert.rule_id}|{','.join(alert.event_ids)}|{alert.group_value}"


def save_alerts(path: Path, alerts: Iterable[Alert]) -> int:
    now = datetime.now(timezone.utc).isoformat()
    rows = [(_alert_key(a), a.rule_id, a.title, a.description, a.severity, a.technique_id,
             a.technique_name, a.first_seen.isoformat(), a.last_seen.isoformat(), a.group_value,
             json.dumps(a.event_ids), a.host, a.user, a.source, now) for a in alerts]
    if not rows: return 0
    with closing(get_connection(path)) as connection, connection:
        before = connection.total_changes
        connection.executemany("INSERT OR IGNORE INTO alerts(alert_key,rule_id,title,description,severity,technique_id,technique_name,first_seen,last_seen,group_value,event_ids,host,username,source,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        return connection.total_changes - before


def replace_alerts(path: Path, alerts: list[Alert]) -> int:
    with closing(get_connection(path)) as connection, connection:
        connection.execute("DELETE FROM alerts")
    return save_alerts(path, alerts)


def list_alerts(path: Path, severity: str | None = None, technique: str | None = None, search: str | None = None) -> list[dict[str, object]]:
    query, clauses, params = "SELECT * FROM alerts", [], []
    if severity: clauses.append("severity = ?"); params.append(severity.title())
    if technique: clauses.append("technique_id = ?"); params.append(technique)
    if search:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        clauses.append("(title LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\' OR source LIKE ? ESCAPE '\\')")
        params.extend([pattern] * 4)
    if clauses: query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY CASE severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,datetime(first_seen) DESC"
    with closing(get_connection(path)) as connection: rows = connection.execute(query, params).fetchall()
    return [dict(row) | {"event_ids": json.loads(str(row["event_ids"]))} for row in rows]


def alert_stats(path: Path) -> dict[str, object]:
    with closing(get_connection(path)) as connection:
        total = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        by_severity = {row["severity"]: row["count"] for row in connection.execute("SELECT severity,COUNT(*) AS count FROM alerts GROUP BY severity")}
        techniques = [{"technique_id": r["technique_id"], "technique_name": r["technique_name"], "count": r["count"]} for r in connection.execute("SELECT technique_id,technique_name,COUNT(*) AS count FROM alerts GROUP BY technique_id,technique_name ORDER BY count DESC,technique_id")]
        event_count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        ioc_count = connection.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    return {"total": int(total), "high": int(by_severity.get("High", 0)), "medium": int(by_severity.get("Medium", 0)), "low": int(by_severity.get("Low", 0)), "techniques": techniques, "events": int(event_count), "iocs": int(ioc_count)}


def import_iocs(path: Path, rows: Iterable[tuple[str, str, str]]) -> int:
    now = datetime.now(timezone.utc).isoformat()
    with closing(get_connection(path)) as connection, connection:
        before = connection.total_changes
        connection.executemany("INSERT OR IGNORE INTO iocs(type,value,source,imported_at) VALUES(?,?,?,?)", [(a,b,c,now) for a,b,c in rows])
        return connection.total_changes - before


def find_iocs(path: Path, values: Iterable[str]) -> list[tuple[str, str, str]]:
    candidates = {str(v).strip().lower() for v in values if str(v).strip()}
    if not candidates: return []
    with closing(get_connection(path)) as connection: rows = connection.execute("SELECT type,value,source FROM iocs").fetchall()
    return [(r["type"], r["value"], r["source"]) for r in rows if r["value"].lower() in candidates]
