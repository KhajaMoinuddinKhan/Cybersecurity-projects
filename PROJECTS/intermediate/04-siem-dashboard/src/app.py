"""Local SIEM dashboard with live event ingestion."""
from __future__ import annotations

import argparse
import csv
import io
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .windows_collector import WindowsEventCollector

EventInput = tuple[str, str, str, str, str]
EventRow = tuple[int, str, str, str, str, str, str, str, str, str, str]
VALID_SEVERITIES = ("High", "Medium", "Low")

SCHEMA = """CREATE TABLE IF NOT EXISTS events (
id INTEGER PRIMARY KEY AUTOINCREMENT,
timestamp TEXT NOT NULL,
source_ip TEXT NOT NULL,
event TEXT NOT NULL,
severity TEXT NOT NULL,
username TEXT NOT NULL,
host TEXT NOT NULL DEFAULT 'unknown',
source TEXT NOT NULL DEFAULT 'manual',
event_type TEXT NOT NULL DEFAULT 'security_event',
raw_log TEXT NOT NULL DEFAULT '',
created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
external_id TEXT NOT NULL DEFAULT ''
)"""

SAMPLE_EVENTS: tuple[EventInput, ...] = (
    ("2026-09-30 09:01", "10.0.0.21", "Repeated failed login", "High", "admin"),
    ("2026-09-30 09:05", "10.0.0.18", "New admin login", "Medium", "admin"),
    ("2026-09-30 09:10", "10.0.0.31", "Large outbound transfer", "High", "analyst"),
    ("2026-09-30 09:14", "10.0.0.9", "Successful login", "Low", "user1"),
)


def get_connection(db_path: Path) -> sqlite3.Connection:
    """Open the database and make sure the current schema exists."""

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute(SCHEMA)

    existing = {
        row["name"] for row in connection.execute("PRAGMA table_info(events)").fetchall()
    }
    additions = {
        "host": "TEXT NOT NULL DEFAULT 'unknown'",
        "source": "TEXT NOT NULL DEFAULT 'manual'",
        "event_type": "TEXT NOT NULL DEFAULT 'security_event'",
        "raw_log": "TEXT NOT NULL DEFAULT ''",
        "created_at": "TEXT NOT NULL DEFAULT ''",
        "external_id": "TEXT NOT NULL DEFAULT ''",
    }
    for name, definition in additions.items():
        if name not in existing:
            connection.execute(f"ALTER TABLE events ADD COLUMN {name} {definition}")

    connection.execute(
        "UPDATE events SET created_at = timestamp WHERE created_at = '' OR created_at IS NULL"
    )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_events_external "
        "ON events(source, external_id) WHERE external_id != ''"
    )
    connection.commit()
    return connection


def normalise_severity(value: str | None) -> str | None:
    """Return a supported severity name."""

    if value is None:
        return None
    candidate = value.strip().title()
    return candidate if candidate in VALID_SEVERITIES else None


def normalise_timestamp(value: Any) -> str:
    """Store timestamps in a consistent UTC-friendly format."""

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


def _normalise_event(row: EventInput) -> EventInput:
    """Clean a tuple event before saving it."""

    timestamp, source_ip, event, severity, username = row
    canonical = normalise_severity(severity)
    if canonical is None:
        raise ValueError(
            f"Unsupported severity {severity!r}. Expected one of: {', '.join(VALID_SEVERITIES)}."
        )

    message = event.strip()
    if not message:
        raise ValueError("Event message cannot be empty")

    return (
        normalise_timestamp(timestamp),
        source_ip.strip() or "unknown",
        message,
        canonical,
        username.strip() or "unknown",
    )


def normalise_payload(
    payload: dict[str, Any],
    source_default: str = "api",
) -> tuple[str, str, str, str, str, str, str, str, str, str]:
    """Convert an API or imported event into a database row."""

    message = str(payload.get("event") or payload.get("message") or "").strip()
    if not message:
        raise ValueError("Event payload needs an 'event' or 'message' value")

    severity_text = str(payload.get("severity") or "Low")
    severity = normalise_severity(severity_text)
    if severity is None:
        raise ValueError(
            f"Unsupported severity {severity_text!r}. Expected High, Medium, or Low."
        )

    raw_log = payload.get("raw_log")
    if raw_log is None:
        raw_log = json.dumps(payload, ensure_ascii=False, sort_keys=True)

    return (
        normalise_timestamp(payload.get("timestamp")),
        str(payload.get("source_ip") or payload.get("ip") or "unknown").strip(),
        message,
        severity,
        str(payload.get("username") or payload.get("user") or "unknown").strip(),
        str(payload.get("host") or payload.get("hostname") or "unknown").strip(),
        str(payload.get("source") or source_default).strip(),
        str(payload.get("event_type") or payload.get("type") or "security_event").strip(),
        str(raw_log),
        str(payload.get("external_id") or "").strip(),
    )


def seed_events(db_path: Path, events: Iterable[EventInput]) -> int:
    """Insert tuple-based events."""

    rows = [_normalise_event(row) for row in events]
    with get_connection(db_path) as connection:
        connection.executemany(
            "INSERT INTO events(timestamp,source_ip,event,severity,username) VALUES (?,?,?,?,?)",
            rows,
        )
    return len(rows)


def ingest_payloads(
    db_path: Path,
    payloads: Iterable[dict[str, Any]],
    source_default: str = "api",
) -> int:
    """Insert structured security events."""

    rows = [normalise_payload(payload, source_default) for payload in payloads]
    if not rows:
        return 0

    with get_connection(db_path) as connection:
        before = connection.total_changes
        connection.executemany(
            """INSERT OR IGNORE INTO events(
                timestamp,source_ip,event,severity,username,host,source,event_type,raw_log,external_id
            ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        inserted = connection.total_changes - before
    return inserted


def parse_event_file(filename: str, content: bytes) -> list[dict[str, Any]]:
    """Read JSON, JSONL, NDJSON, or CSV event files."""

    if len(content) > 2_000_000:
        raise ValueError("Import file is too large. Keep it under 2 MB.")

    suffix = Path(filename).suffix.lower()
    text = content.decode("utf-8-sig")

    if suffix == ".json":
        data = json.loads(text)
        if isinstance(data, dict) and "events" in data:
            data = data["events"]
        elif isinstance(data, dict):
            data = [data]
        if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
            raise ValueError("JSON import must contain an event object or a list of event objects")
        return data

    if suffix in {".jsonl", ".ndjson"}:
        rows: list[dict[str, Any]] = []
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError(f"Line {line_number} is not a JSON object")
            rows.append(item)
        return rows

    if suffix == ".csv":
        return [dict(row) for row in csv.DictReader(io.StringIO(text))]

    raise ValueError("Supported imports: .json, .jsonl, .ndjson, and .csv")


def reset_events(db_path: Path) -> None:
    """Delete stored events and restart event IDs."""

    with get_connection(db_path) as connection:
        connection.execute("DELETE FROM events")
        connection.execute("DELETE FROM sqlite_sequence WHERE name = 'events'")


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _build_filters(
    severity: str | None = None,
    search: str | None = None,
    source: str | None = None,
    event_type: str | None = None,
    username: str | None = None,
    since_minutes: int | None = None,
) -> tuple[list[str], list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []

    canonical = normalise_severity(severity)
    if canonical:
        clauses.append("severity = ?")
        params.append(canonical)

    if search and search.strip():
        pattern = f"%{_escape_like(search.strip())}%"
        clauses.append(
            "(source_ip LIKE ? ESCAPE '\\' OR event LIKE ? ESCAPE '\\' "
            "OR username LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\' "
            "OR source LIKE ? ESCAPE '\\' OR event_type LIKE ? ESCAPE '\\')"
        )
        params.extend([pattern] * 6)

    if source and source.strip():
        clauses.append("source = ?")
        params.append(source.strip())

    if event_type and event_type.strip():
        clauses.append("event_type = ?")
        params.append(event_type.strip())

    if username and username.strip():
        clauses.append("username = ?")
        params.append(username.strip())

    if since_minutes is not None:
        clauses.append("datetime(timestamp) >= datetime('now', ?)")
        params.append(f"-{since_minutes} minutes")

    return clauses, params


def query_events(
    db_path: Path,
    severity: str | None = None,
    search: str | None = None,
    source: str | None = None,
    event_type: str | None = None,
    username: str | None = None,
    since_minutes: int | None = None,
    limit: int = 500,
) -> list[EventRow]:
    """Return events matching the current filters."""

    clauses, params = _build_filters(
        severity, search, source, event_type, username, since_minutes
    )
    query = (
        "SELECT id,timestamp,source_ip,event,severity,username,host,source,"
        "event_type,raw_log,created_at,external_id FROM events"
    )
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY datetime(timestamp) DESC, id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 2000)))

    with get_connection(db_path) as connection:
        rows = connection.execute(query, params).fetchall()

    return [
        (
            int(row["id"]),
            str(row["timestamp"]),
            str(row["source_ip"]),
            str(row["event"]),
            str(row["severity"]),
            str(row["username"]),
            str(row["host"]),
            str(row["source"]),
            str(row["event_type"]),
            str(row["raw_log"]),
            str(row["created_at"]),
            str(row["external_id"]),
        )
        for row in rows
    ]


def severity_counts(
    db_path: Path,
    search: str | None = None,
    source: str | None = None,
    event_type: str | None = None,
    username: str | None = None,
    since_minutes: int | None = None,
    severity: str | None = None,
) -> dict[str, int]:
    """Count events for the active filters."""

    clauses, params = _build_filters(
        severity, search, source, event_type, username, since_minutes
    )
    where = " WHERE " + " AND ".join(clauses) if clauses else ""

    counts = {"High": 0, "Medium": 0, "Low": 0}
    with get_connection(db_path) as connection:
        grouped = connection.execute(
            "SELECT severity, COUNT(*) AS count FROM events"
            + where
            + " GROUP BY severity",
            params,
        ).fetchall()
        total = int(
            connection.execute(
                "SELECT COUNT(*) AS count FROM events" + where,
                params,
            ).fetchone()["count"]
        )

    for row in grouped:
        if row["severity"] in counts:
            counts[str(row["severity"])] = int(row["count"])
    counts["Total"] = total
    return counts


def _dimension_values(db_path: Path, column: str) -> list[str]:
    if column not in {"source", "event_type", "username"}:
        raise ValueError("Unsupported dimension")
    with get_connection(db_path) as connection:
        rows = connection.execute(
            f"SELECT DISTINCT {column} AS value FROM events "
            f"WHERE {column} != '' ORDER BY {column} LIMIT 100"
        ).fetchall()
    return [str(row["value"]) for row in rows]


def _top_values(
    db_path: Path,
    column: str,
    clauses: list[str],
    params: list[Any],
    limit: int = 6,
) -> list[dict[str, Any]]:
    if column not in {"source_ip", "username", "event_type", "source"}:
        raise ValueError("Unsupported top-value column")
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with get_connection(db_path) as connection:
        rows = connection.execute(
            f"SELECT {column} AS label, COUNT(*) AS count FROM events"
            + where
            + f" GROUP BY {column} ORDER BY count DESC, {column} LIMIT ?",
            [*params, limit],
        ).fetchall()
    return [{"label": str(row["label"]), "count": int(row["count"])} for row in rows]


def _timeline(
    db_path: Path,
    clauses: list[str],
    params: list[Any],
    points: int = 12,
) -> list[dict[str, Any]]:
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with get_connection(db_path) as connection:
        rows = connection.execute(
            "SELECT substr(timestamp,1,13) AS bucket, COUNT(*) AS count FROM events"
            + where
            + " GROUP BY bucket ORDER BY bucket DESC LIMIT ?",
            [*params, points],
        ).fetchall()

    return [
        {"label": str(row["bucket"]).replace("T", " "), "count": int(row["count"])}
        for row in reversed(rows)
    ]


def dashboard_snapshot(
    db_path: Path,
    severity: str | None = None,
    search: str | None = None,
    source: str | None = None,
    event_type: str | None = None,
    username: str | None = None,
    since_minutes: int | None = None,
    limit: int = 250,
) -> dict[str, Any]:
    """Build the JSON payload used by the live dashboard."""

    rows = query_events(
        db_path,
        severity=severity,
        search=search,
        source=source,
        event_type=event_type,
        username=username,
        since_minutes=since_minutes,
        limit=limit,
    )
    counts = severity_counts(
        db_path,
        search=search,
        source=source,
        event_type=event_type,
        username=username,
        since_minutes=since_minutes,
        severity=severity,
    )
    filter_counts = severity_counts(
        db_path,
        search=search,
        source=source,
        event_type=event_type,
        username=username,
        since_minutes=since_minutes,
    )
    clauses, params = _build_filters(
        severity, search, source, event_type, username, since_minutes
    )

    events = [
        {
            "id": row[0],
            "timestamp": row[1],
            "source_ip": row[2],
            "event": row[3],
            "severity": row[4],
            "username": row[5],
            "host": row[6],
            "source": row[7],
            "event_type": row[8],
            "raw_log": row[9],
            "created_at": row[10],
            "external_id": row[11],
        }
        for row in rows
    ]

    return {
        "counts": counts,
        "filter_counts": filter_counts,
        "events": events,
        "visible": len(events),
        "dimensions": {
            "sources": _dimension_values(db_path, "source"),
            "event_types": _dimension_values(db_path, "event_type"),
            "usernames": _dimension_values(db_path, "username"),
        },
        "top_sources": _top_values(db_path, "source_ip", clauses, params),
        "top_event_types": _top_values(db_path, "event_type", clauses, params),
        "timeline": _timeline(db_path, clauses, params),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def dashboard_app(db_path: Path, collector_status: dict[str, Any] | None = None):
    """Create the Flask SIEM application."""

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
    app.config["MAX_CONTENT_LENGTH"] = 2_000_000

    @app.get("/")
    def index():
        return render_template("dashboard.html")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/api/dashboard")
    def api_dashboard():
        since_text = request.args.get("since", "").strip()
        since_minutes = int(since_text) if since_text.isdigit() else None
        snapshot = dashboard_snapshot(
                db_path,
                severity=request.args.get("severity") or None,
                search=request.args.get("search") or None,
                source=request.args.get("source") or None,
                event_type=request.args.get("event_type") or None,
                username=request.args.get("username") or None,
                since_minutes=since_minutes,
            )
        snapshot["collector"] = collector_status or {
            "enabled": False,
            "running": False,
            "ingested": 0,
            "logs": {},
            "last_error": "",
        }
        return jsonify(snapshot)

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
            inserted = ingest_payloads(db_path, payloads, "api")
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
            inserted = ingest_payloads(db_path, payloads, f"import:{uploaded.filename}")
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"inserted": inserted}), 201

    @app.post("/api/events/clear")
    def api_clear():
        reset_events(db_path)
        return jsonify({"cleared": True})

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local MKMK SIEM dashboard.")
    parser.add_argument("--db", type=Path, default=Path("siem.db"))
    parser.add_argument("--seed", action="store_true")
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument(
        "--no-windows-events",
        action="store_true",
        help="Do not collect new local Windows Event Log entries.",
    )
    args = parser.parse_args()

    get_connection(args.db).close()

    if args.reset:
        reset_events(args.db)
        print("Cleared existing events.")
    if args.seed:
        print(f"Seeded {seed_events(args.db, SAMPLE_EVENTS)} optional lab events.")

    collector = WindowsEventCollector(args.db, ingest_payloads)
    if not args.no_windows_events:
        collector.start()

    try:
        dashboard_app(args.db, collector.status).run(
            host=args.host,
            port=args.port,
            debug=False,
            threaded=True,
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    finally:
        collector.stop()


if __name__ == "__main__":
    main()
