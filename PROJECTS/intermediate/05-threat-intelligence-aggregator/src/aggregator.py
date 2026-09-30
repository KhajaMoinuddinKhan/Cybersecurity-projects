"""Import and search IOC data with SQLite."""
from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from pathlib import Path
from typing import Iterable

# Keep the stored indicator types predictable.
VALID_TYPES = {"ip", "domain", "hash", "url"}

SCHEMA = """CREATE TABLE IF NOT EXISTS iocs (
id INTEGER PRIMARY KEY AUTOINCREMENT,
type TEXT NOT NULL,
value TEXT NOT NULL,
source TEXT NOT NULL,
UNIQUE(type,value))"""

def get_connection(db_path: Path) -> sqlite3.Connection:
    """Open the database and create the table if needed."""

    connection = sqlite3.connect(db_path)
    connection.execute(SCHEMA)
    connection.commit()
    return connection

def normalise_row(row: dict[str, str]) -> tuple[str, str, str]:
    """Clean one IOC row before saving it."""

    kind = row.get("type", "").strip().lower()
    value = row.get("value", "").strip()
    source = row.get("source", "local").strip() or "local"

    if kind not in VALID_TYPES:
        raise ValueError(f"Unsupported IOC type: {kind!r}")
    if not value:
        raise ValueError("IOC value cannot be empty")

    return kind, value, source

def read_feed(path: Path) -> list[tuple[str, str, str]]:
    """Read IOC rows from JSON or CSV."""

    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError("JSON feed must be a list")
        if not all(isinstance(item, dict) for item in data):
            raise ValueError("Every JSON feed item must be an object")
        return [normalise_row(item) for item in data]

    with path.open(newline="", encoding="utf-8") as handle:
        return [normalise_row(row) for row in csv.DictReader(handle)]

def import_iocs(
    db_path: Path,
    rows: Iterable[tuple[str, str, str]],
) -> int:
    """Insert new indicators and skip duplicates."""

    rows = list(rows)
    with get_connection(db_path) as connection:
        before = connection.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]

        # The database uniqueness rule drops duplicate indicators.
        connection.executemany(
            "INSERT OR IGNORE INTO iocs(type,value,source) VALUES (?,?,?)",
            rows,
        )
        after = connection.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]

    return after - before

def _escape_like(value: str) -> str:
    """Escape SQL wildcard characters in search text."""

    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

def search_iocs(db_path: Path, term: str) -> list[tuple[str, str, str]]:
    """Search stored indicator values."""

    pattern = f"%{_escape_like(term)}%"
    with get_connection(db_path) as connection:
        return connection.execute(
            "SELECT type,value,source FROM iocs "
            "WHERE value LIKE ? ESCAPE '\\' ORDER BY type,value",
            (pattern,),
        ).fetchall()

def main() -> None:
    """Import a feed or search the local database."""

    parser = argparse.ArgumentParser(description="Import and search local IOC feeds.")
    parser.add_argument("--db", type=Path, default=Path("threat_intel.db"))
    parser.add_argument("--feed", type=Path)
    parser.add_argument("--search")
    args = parser.parse_args()

    if not args.feed and not args.search:
        parser.error("Use --feed and/or --search")

    if args.feed:
        print(f"Imported {import_iocs(args.db, read_feed(args.feed))} new IOCs.")

    if args.search:
        results = search_iocs(args.db, args.search)
        if not results:
            print("No matching IOCs found.")
        for row in results:
            print(f"{row[0]:7} {row[1]:40} {row[2]}")

if __name__ == "__main__":
    main()
