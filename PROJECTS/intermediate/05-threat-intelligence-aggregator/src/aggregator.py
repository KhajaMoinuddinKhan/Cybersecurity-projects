"""Import and search simple IOC feeds in SQLite."""
from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from pathlib import Path
from typing import Iterable


# [SECTION] IOC types and storage schema
# Restricting IOC categories keeps the local database predictable and easier to query.
VALID_TYPES = {"ip", "domain", "hash", "url"}

SCHEMA = """CREATE TABLE IF NOT EXISTS iocs (
id INTEGER PRIMARY KEY AUTOINCREMENT,
type TEXT NOT NULL,
value TEXT NOT NULL,
source TEXT NOT NULL,
UNIQUE(type,value))"""


def get_connection(db_path: Path) -> sqlite3.Connection:
    """Open the SQLite database and ensure the IOC table exists."""

    connection = sqlite3.connect(db_path)
    connection.execute(SCHEMA)
    connection.commit()
    return connection


# [SECTION] Feed normalization
def normalise_row(row: dict[str, str]) -> tuple[str, str, str]:
    """Validate and normalize one feed record before it enters the database."""

    kind = row.get("type", "").strip().lower()
    value = row.get("value", "").strip()
    source = row.get("source", "local").strip() or "local"

    if kind not in VALID_TYPES:
        raise ValueError(f"Unsupported IOC type: {kind!r}")
    if not value:
        raise ValueError("IOC value cannot be empty")

    return kind, value, source


def read_feed(path: Path) -> list[tuple[str, str, str]]:
    """Read IOC rows from either JSON or CSV and normalize every record."""

    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError("JSON feed must be a list")
        return [normalise_row(dict(item)) for item in data]

    with path.open(newline="", encoding="utf-8") as handle:
        return [normalise_row(row) for row in csv.DictReader(handle)]


# [SECTION] IOC ingestion
def import_iocs(
    db_path: Path,
    rows: Iterable[tuple[str, str, str]],
) -> int:
    """Insert unique IOCs and return how many new database rows were created."""

    rows = list(rows)
    with get_connection(db_path) as connection:
        before = connection.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]

        # INSERT OR IGNORE works with the UNIQUE(type, value) rule to deduplicate IOCs.
        connection.executemany(
            "INSERT OR IGNORE INTO iocs(type,value,source) VALUES (?,?,?)",
            rows,
        )
        after = connection.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]

    return after - before


# [SECTION] IOC lookup
def search_iocs(db_path: Path, term: str) -> list[tuple[str, str, str]]:
    """Search IOC values using a parameterized SQL LIKE query."""

    with get_connection(db_path) as connection:
        return connection.execute(
            "SELECT type,value,source FROM iocs "
            "WHERE value LIKE ? ORDER BY type,value",
            (f"%{term}%",),
        ).fetchall()


# [SECTION] Command-line interface
def main() -> None:
    """Import a feed, search stored indicators, or perform both operations."""

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
