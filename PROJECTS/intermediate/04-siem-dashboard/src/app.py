"""Local SIEM dashboard using synthetic events."""
from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from typing import Iterable
from urllib.parse import urlencode

EventInput = tuple[str, str, str, str, str]
EventRow = tuple[int, str, str, str, str, str]
VALID_SEVERITIES = ("High", "Medium", "Low")

# SQLite keeps the demo self-contained.
SCHEMA = """CREATE TABLE IF NOT EXISTS events (
id INTEGER PRIMARY KEY AUTOINCREMENT,
timestamp TEXT NOT NULL,
source_ip TEXT NOT NULL,
event TEXT NOT NULL,
severity TEXT NOT NULL,
username TEXT NOT NULL)"""

# One shared sample set is used by both entry points.
SAMPLE_EVENTS: tuple[EventInput, ...] = (
    ("2026-09-30 09:01", "10.0.0.21", "Repeated failed login", "High", "admin"),
    ("2026-09-30 09:05", "10.0.0.18", "New admin login", "Medium", "admin"),
    ("2026-09-30 09:10", "10.0.0.31", "Large outbound transfer", "High", "analyst"),
    ("2026-09-30 09:14", "10.0.0.9", "Successful login", "Low", "user1"),
    (
        "2026-09-30 09:20",
        "10.0.0.55",
        "Suspicious PowerShell execution",
        "High",
        "svc-backup",
    ),
    ("2026-09-30 09:24", "10.0.0.41", "Password reset request", "Low", "jane"),
    (
        "2026-09-30 09:28",
        "10.0.0.77",
        "Multiple VPN authentication failures",
        "High",
        "remote-user",
    ),
    ("2026-09-30 09:35", "10.0.0.16", "New device enrolled", "Medium", "it-support"),
    (
        "2026-09-30 09:42",
        "10.0.0.63",
        "Unusual login time detected",
        "Medium",
        "developer",
    ),
    (
        "2026-09-30 09:48",
        "10.0.0.84",
        "Endpoint malware scan completed",
        "Low",
        "system",
    ),
    (
        "2026-09-30 09:54",
        "10.0.0.46",
        "Unsigned script execution blocked",
        "High",
        "engineer",
    ),
    (
        "2026-09-30 10:02",
        "10.0.0.12",
        "Privilege group membership changed",
        "Medium",
        "helpdesk",
    ),
)

def get_connection(db_path: Path) -> sqlite3.Connection:
    """Open the database and create the table if needed."""

    connection = sqlite3.connect(db_path)
    connection.execute(SCHEMA)
    connection.commit()
    return connection

def normalise_severity(value: str | None) -> str | None:
    """Normalize a severity value."""

    if value is None:
        return None

    candidate = value.strip().title()
    return candidate if candidate in VALID_SEVERITIES else None

def _normalise_event(row: EventInput) -> EventInput:
    """Clean one event before saving it."""

    timestamp, source_ip, event, severity, username = row
    canonical_severity = normalise_severity(severity)
    if canonical_severity is None:
        supported = ", ".join(VALID_SEVERITIES)
        raise ValueError(
            f"Unsupported severity {severity!r}. Expected one of: {supported}."
        )

    return (
        timestamp.strip(),
        source_ip.strip(),
        event.strip(),
        canonical_severity,
        username.strip(),
    )

def _escape_like(value: str) -> str:
    """Escape wildcard characters in search text."""

    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

def seed_events(
    db_path: Path,
    events: Iterable[EventInput],
) -> int:
    """Insert events into the database."""

    rows = [_normalise_event(row) for row in events]
    with get_connection(db_path) as connection:
        connection.executemany(
            "INSERT INTO events(timestamp,source_ip,event,severity,username) "
            "VALUES (?,?,?,?,?)",
            rows,
        )
    return len(rows)

def reset_events(db_path: Path) -> None:
    """Clear the event table and restart IDs."""

    with get_connection(db_path) as connection:
        connection.execute("DELETE FROM events")
        # Start fresh demos at event ID 1.
        connection.execute("DELETE FROM sqlite_sequence WHERE name = 'events'")

def query_events(
    db_path: Path,
    severity: str | None = None,
    search: str | None = None,
) -> list[EventRow]:
    """Get events using the selected filters."""

    query = "SELECT id,timestamp,source_ip,event,severity,username FROM events"
    clauses: list[str] = []
    params: list[str] = []

    canonical_severity = normalise_severity(severity)
    if canonical_severity:
        clauses.append("severity = ?")
        params.append(canonical_severity)

    search_text = search.strip() if search else ""
    if search_text:
        clauses.append(
            "(source_ip LIKE ? ESCAPE '\\' "
            "OR event LIKE ? ESCAPE '\\' "
            "OR username LIKE ? ESCAPE '\\')"
        )
        pattern = f"%{_escape_like(search_text)}%"
        params.extend([pattern, pattern, pattern])

    if clauses:
        query += " WHERE " + " AND ".join(clauses)

    query += " ORDER BY id DESC"

    with get_connection(db_path) as connection:
        rows = connection.execute(query, params).fetchall()

    return [
        (
            int(row[0]),
            str(row[1]),
            str(row[2]),
            str(row[3]),
            str(row[4]),
            str(row[5]),
        )
        for row in rows
    ]

def severity_counts(db_path: Path) -> dict[str, int]:
    """Count events by severity."""

    counts = {"High": 0, "Medium": 0, "Low": 0}
    with get_connection(db_path) as connection:
        grouped_rows = connection.execute(
            "SELECT severity, COUNT(*) FROM events GROUP BY severity"
        ).fetchall()
        total = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    for severity, count in grouped_rows:
        if severity in counts:
            counts[str(severity)] = int(count)

    # Total includes every stored row.
    counts["Total"] = total
    return counts

def build_filter_link(severity: str | None, search: str) -> str:
    """Build a filter link for the dashboard."""

    params: dict[str, str] = {}
    canonical_severity = normalise_severity(severity)
    if canonical_severity:
        params["severity"] = canonical_severity

    search_text = search.strip()
    if search_text:
        params["search"] = search_text

    return "/?" + urlencode(params) if params else "/"

def dashboard_app(db_path: Path):
    """Create the Flask dashboard."""

    try:
        from flask import Flask, render_template, request
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

    @app.get("/")
    def index():
        """Render the dashboard."""

        severity = normalise_severity(request.args.get("severity"))
        search = request.args.get("search", "").strip()

        rows = query_events(
            db_path,
            severity=severity,
            search=search or None,
        )
        counts = severity_counts(db_path)
        total = max(counts["Total"], 1)

        return render_template(
            "dashboard.html",
            rows=rows,
            counts=counts,
            current_severity=severity or "",
            search=search,
            current_view=severity or "All Events",
            high_width=(counts["High"] / total) * 100,
            medium_width=(counts["Medium"] / total) * 100,
            low_width=(counts["Low"] / total) * 100,
            build_filter_link=build_filter_link,
        )

    return app

def main() -> None:
    """Prepare the database and start the dashboard."""

    parser = argparse.ArgumentParser(description="Run the local MKMK SIEM dashboard.")
    parser.add_argument("--db", type=Path, default=Path("siem.db"))
    parser.add_argument("--seed", action="store_true")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Clear existing events before starting or seeding the dashboard.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    get_connection(args.db).close()

    if args.reset:
        reset_events(args.db)
        print("Cleared existing events.")

    if args.seed:
        print(f"Seeded {seed_events(args.db, SAMPLE_EVENTS)} events.")

    try:
        dashboard_app(args.db).run(
            host=args.host,
            port=args.port,
            debug=False,
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc

if __name__ == "__main__":
    main()
