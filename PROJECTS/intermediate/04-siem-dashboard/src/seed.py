"""Seed the local MKMK SIEM dashboard with synthetic security events."""
from __future__ import annotations

import argparse
from pathlib import Path

from app import SAMPLE_EVENTS, get_connection, reset_events, seed_events


# [SECTION] Command-line seed utility
def main() -> None:
    """Create the database and insert the shared synthetic analyst dataset."""

    parser = argparse.ArgumentParser(
        description="Insert synthetic events into the local SIEM database."
    )
    parser.add_argument("--db", type=Path, default=Path("siem.db"))
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Clear existing events before inserting the demo dataset.",
    )
    args = parser.parse_args()

    get_connection(args.db).close()

    if args.reset:
        reset_events(args.db)
        print("Cleared existing events.")

    inserted = seed_events(args.db, SAMPLE_EVENTS)
    print(f"Inserted {inserted} sample events into {args.db}.")


if __name__ == "__main__":
    main()
