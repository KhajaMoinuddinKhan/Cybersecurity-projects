"""Local SIEM console backed by live event data."""
from __future__ import annotations

import argparse
import csv
import io
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .windows_collector import WindowsEventCollector

VALID_SEVERITIES = ("High", "Medium", "Low")

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
created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)"""


def get_connection(db_path: Path) -> sqlite3.Connection:
    """Open the live event store."""

    connection = sqlite3.connect(db_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute(SCHEMA)
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
    )


def ingest_payloads(
    db_path: Path,
    payloads: Iterable[dict[str, Any]],
    source_default: str = "api",
) -> int:
    """Insert structured events and ignore collector duplicates."""

    rows = [normalise_payload(payload, source_default) for payload in payloads]
    if not rows:
        return 0

    with closing(get_connection(db_path)) as connection, connection:
        before = connection.total_changes
        connection.executemany(
            """INSERT OR IGNORE INTO live_events(
                timestamp,channel,provider,event_id,level,severity,username,host,
                source_ip,message,record_id,source,is_alert,rule_name,raw_log,external_id
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        inserted = connection.total_changes - before
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


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _filters(
    severity: str | None = None,
    search: str | None = None,
    channel: str | None = None,
    provider: str | None = None,
    event_id: str | None = None,
    username: str | None = None,
    since_minutes: int | None = None,
    alerts_only: bool = False,
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
            "OR channel LIKE ? ESCAPE '\\' OR rule_name LIKE ? ESCAPE '\\')"
        )
        params.extend([pattern] * 8)

    for column, value in (
        ("channel", channel),
        ("provider", provider),
        ("event_id", event_id),
        ("username", username),
    ):
        if value and value.strip():
            clauses.append(f"{column} = ?")
            params.append(value.strip())

    if since_minutes is not None:
        clauses.append("datetime(timestamp) >= datetime('now', ?)")
        params.append(f"-{since_minutes} minutes")

    if alerts_only:
        clauses.append("is_alert = 1")

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
    limit: int = 300,
) -> list[dict[str, Any]]:
    """Return live events matching the active filters."""

    clauses, params = _filters(
        severity, search, channel, provider, event_id, username, since_minutes, alerts_only
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
) -> dict[str, int]:
    clauses, params = _filters(
        severity, search, channel, provider, event_id, username, since_minutes, alerts_only
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
    allowed = {"channel", "provider", "event_id", "username"}
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
    if column not in {"provider", "event_id", "username", "channel"}:
        raise ValueError("Unsupported ranking field")

    with closing(get_connection(db_path)) as connection, connection:
        rows = connection.execute(
            f"SELECT {column} AS label, COUNT(*) AS count FROM live_events"
            + _where(clauses)
            + f" GROUP BY {column} ORDER BY count DESC, {column} LIMIT ?",
            [*params, limit],
        ).fetchall()
    return [{"label": str(row["label"]), "count": int(row["count"])} for row in rows]


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
        severity, search, channel, provider, event_id, username, since_minutes, alerts_only
    )
    alert_clauses = [*clauses, "is_alert = 1"]
    alert_params = list(params)

    recent_clauses, recent_params = _filters(
        severity, search, channel, provider, event_id, username, 1, alerts_only
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
            limit=30,
        ),
        "alert_count": _count_rows(db_path, alert_clauses, alert_params),
        "events_per_minute": _count_rows(db_path, recent_clauses, recent_params),
        "events": events,
        "visible": len(events),
        "dimensions": {
            "channels": _dimension_values(db_path, "channel"),
            "providers": _dimension_values(db_path, "provider"),
            "event_ids": _dimension_values(db_path, "event_id"),
            "usernames": _dimension_values(db_path, "username"),
        },
        "top_providers": _top_values(db_path, "provider", clauses, params),
        "top_event_ids": _top_values(db_path, "event_id", clauses, params),
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


def dashboard_app(db_path: Path, collector_status: dict[str, Any] | None = None):
    """Create the Flask application."""

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
        return render_template("dashboard.html")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "database": str(db_path)})

    @app.get("/api/dashboard")
    def api_dashboard():
        since_text = request.args.get("since", "").strip()
        since_minutes = int(since_text) if since_text.isdigit() else None
        snapshot = dashboard_snapshot(
            db_path,
            severity=request.args.get("severity") or None,
            search=request.args.get("search") or None,
            channel=request.args.get("channel") or None,
            provider=request.args.get("provider") or None,
            event_id=request.args.get("event_id") or None,
            username=request.args.get("username") or None,
            since_minutes=since_minutes,
            alerts_only=request.args.get("alerts") == "1",
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
            inserted = ingest_payloads(
                db_path,
                payloads,
                f"import:{uploaded.filename}",
            )
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"inserted": inserted}), 201

    @app.post("/api/events/clear")
    def api_clear():
        reset_events(db_path)
        return jsonify({"cleared": True})

    return app


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
    args = parser.parse_args()

    get_connection(args.db).close()
    if args.reset:
        reset_events(args.db)
        print("Cleared the live event store.")

    collector = WindowsEventCollector(args.db, ingest_payloads)
    if not args.no_windows_events:
        collector.start()

    try:
        print(f"SIEM database: {args.db}")
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
