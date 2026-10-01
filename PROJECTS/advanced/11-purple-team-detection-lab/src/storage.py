"""SQLite storage for alerts."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import Alert


SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    group_value TEXT NOT NULL,
    event_ids TEXT NOT NULL,
    host TEXT NOT NULL,
    username TEXT NOT NULL,
    source TEXT NOT NULL
)
"""


def get_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute(SCHEMA)
    connection.commit()
    return connection


def replace_alerts(path: Path, alerts: list[Alert]) -> int:
    with get_connection(path) as connection:
        connection.execute("DELETE FROM alerts")
        connection.execute("DELETE FROM sqlite_sequence WHERE name='alerts'")
        connection.executemany(
            """
            INSERT INTO alerts (
                rule_id, title, description, severity, technique_id, technique_name,
                first_seen, last_seen, group_value, event_ids, host, username, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    alert.rule_id,
                    alert.title,
                    alert.description,
                    alert.severity,
                    alert.technique_id,
                    alert.technique_name,
                    alert.first_seen.isoformat(),
                    alert.last_seen.isoformat(),
                    alert.group_value,
                    json.dumps(alert.event_ids),
                    alert.host,
                    alert.user,
                    alert.source,
                )
                for alert in alerts
            ],
        )
    return len(alerts)


def list_alerts(
    path: Path,
    severity: str | None = None,
    technique: str | None = None,
    search: str | None = None,
) -> list[dict[str, object]]:
    query = "SELECT * FROM alerts"
    clauses: list[str] = []
    params: list[str] = []

    if severity:
        clauses.append("severity = ?")
        params.append(severity.title())
    if technique:
        clauses.append("technique_id = ?")
        params.append(technique)
    if search:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        clauses.append(
            "(title LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\' "
            "OR username LIKE ? ESCAPE '\\' OR source LIKE ? ESCAPE '\\')"
        )
        params.extend([pattern, pattern, pattern, pattern])

    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY CASE severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, first_seen DESC"

    with get_connection(path) as connection:
        rows = connection.execute(query, params).fetchall()

    results: list[dict[str, object]] = []
    for row in rows:
        item = dict(row)
        item["event_ids"] = json.loads(str(item["event_ids"]))
        results.append(item)
    return results


def alert_stats(path: Path) -> dict[str, object]:
    with get_connection(path) as connection:
        total = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        by_severity = {
            row["severity"]: row["count"]
            for row in connection.execute(
                "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity"
            ).fetchall()
        }
        techniques = [
            {"technique_id": row["technique_id"], "technique_name": row["technique_name"], "count": row["count"]}
            for row in connection.execute(
                "SELECT technique_id, technique_name, COUNT(*) AS count FROM alerts "
                "GROUP BY technique_id, technique_name ORDER BY count DESC, technique_id"
            ).fetchall()
        ]

    return {
        "total": int(total),
        "high": int(by_severity.get("High", 0)),
        "medium": int(by_severity.get("Medium", 0)),
        "low": int(by_severity.get("Low", 0)),
        "techniques": techniques,
    }
