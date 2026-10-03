"""Aggregate threat-intelligence indicator feeds into a searchable SQLite store.

A feed is any CSV or JSON document with ``type`` and ``value`` fields. Point the
tool at several files, several URLs and a directory in one run: it normalises and
validates each indicator by type, merges duplicates across sources, scores them
by how many independent sources reported them and how fresh they are, and lets
you search, summarise, export or expire the result.

This aggregates the feeds you hand it. It is not a subscription to a commercial
intelligence provider, and a stored indicator means only that the value appeared
in a feed you imported.
"""
from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

# Keep the stored indicator types predictable.
VALID_TYPES = {"ip", "domain", "hash", "url"}

# Hash length in hexadecimal characters -> algorithm name.
HASH_ALGORITHMS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

# Confidence is half source breadth and half freshness. Three independent
# sources reach the maximum source score; freshness decays linearly over 30 days.
CONFIDENCE_SOURCE_TARGET = 3
CONFIDENCE_FRESH_DAYS = 30.0

DEFAULT_HTTP_TIMEOUT = 15.0
DEFAULT_EXPIRE_DAYS = 90

AGE_BAND_LABELS = ["0-7d", "7-30d", "30-90d", "90d+", "unknown"]

EXPORT_FIELDS = [
    "type",
    "value",
    "source",
    "sources",
    "first_seen",
    "last_seen",
    "observations",
    "confidence",
    "age_days",
    "age_band",
]

SCHEMA = """CREATE TABLE IF NOT EXISTS iocs (
id INTEGER PRIMARY KEY AUTOINCREMENT,
type TEXT NOT NULL,
value TEXT NOT NULL,
source TEXT NOT NULL,
first_seen TEXT,
last_seen TEXT,
observations INTEGER NOT NULL DEFAULT 1,
confidence REAL NOT NULL DEFAULT 0.0,
UNIQUE(type,value))"""

# One row per (indicator, source) so a merged indicator can name every feed that
# reported it. The ``iocs`` table keeps a single ``source`` column for the first
# feed that reported the indicator, which keeps the older readers working.
SOURCE_SCHEMA = """CREATE TABLE IF NOT EXISTS ioc_sources (
type TEXT NOT NULL,
value TEXT NOT NULL,
source TEXT NOT NULL,
first_seen TEXT,
last_seen TEXT,
observations INTEGER NOT NULL DEFAULT 1,
UNIQUE(type,value,source))"""

# Columns added on top of the original four-column ``iocs`` table. Existing
# stores are upgraded in place, so a database written by an earlier version of
# this tool (or read by the SIEM dashboard) keeps working.
_IOC_COLUMNS = {
    "first_seen": "TEXT",
    "last_seen": "TEXT",
    "observations": "INTEGER NOT NULL DEFAULT 1",
    "confidence": "REAL NOT NULL DEFAULT 0.0",
}


class FeedFetchError(ValueError):
    """A feed URL could not be retrieved."""


@dataclass
class Skipped:
    """A feed row that was rejected, and why."""

    source: str
    reason: str
    raw: str = ""


@dataclass
class FeedResult:
    """Accepted indicators and rejected rows from one feed."""

    indicators: list[tuple[str, str, str]] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)


@dataclass
class ImportResult:
    """The outcome of importing a batch of indicators."""

    new: int = 0
    updated: int = 0
    skipped: list[Skipped] = field(default_factory=list)


@dataclass
class SearchHit:
    """One stored indicator, with the metadata needed to judge it."""

    type: str
    value: str
    source: str
    sources: list[str]
    first_seen: str | None
    last_seen: str | None
    observations: int
    confidence: float
    age_days: float | None
    age_band: str


@dataclass
class ExpiredIndicator:
    """An indicator removed by expiry."""

    type: str
    value: str
    source: str
    last_seen: str


@dataclass
class Stats:
    """Counts by type, by source and by age band."""

    total: int
    by_type: list[tuple[str, int]]
    by_source: list[tuple[str, int]]
    by_age: list[tuple[str, int]]


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


def utcnow() -> datetime:
    """The current time, in UTC."""

    return datetime.now(timezone.utc)


def to_iso(moment: datetime) -> str:
    """Format a moment as a sortable UTC timestamp."""

    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text: str | None) -> datetime | None:
    """Read a timestamp written by :func:`to_iso`, or None if unreadable."""

    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def age_days(last_seen: datetime | None, now: datetime) -> float | None:
    """How many days ago an indicator was last seen, or None if unknown."""

    if last_seen is None:
        return None
    return (now - last_seen).total_seconds() / 86400.0


def age_band(age: float | None) -> str:
    """Bucket an age in days into one of the report bands."""

    if age is None:
        return "unknown"
    if age < 7:
        return "0-7d"
    if age < 30:
        return "7-30d"
    if age < 90:
        return "30-90d"
    return "90d+"


def compute_confidence(
    source_count: int, last_seen: datetime | None, now: datetime
) -> float:
    """Score an indicator from source breadth and freshness.

    ``0.6 * min(1, sources / 3) + 0.4 * max(0, 1 - age_days / 30)``, rounded to
    two places. One fresh source scores 0.6, three fresh sources score 1.0, and
    an indicator unseen for 30 days loses all of its freshness weight.
    """

    source_score = min(1.0, source_count / CONFIDENCE_SOURCE_TARGET)
    age = age_days(last_seen, now)
    if age is None:
        freshness = 0.0
    else:
        freshness = max(0.0, 1.0 - age / CONFIDENCE_FRESH_DAYS)
    return round(0.6 * source_score + 0.4 * freshness, 2)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


def get_connection(db_path: Path) -> sqlite3.Connection:
    """Open the database, create the tables and upgrade an older schema."""

    connection = sqlite3.connect(db_path)
    connection.execute(SCHEMA)
    _migrate(connection)
    connection.commit()
    return connection


def _migrate(connection: sqlite3.Connection) -> None:
    """Add the newer columns to a store written by an earlier version."""

    existing = {row[1] for row in connection.execute("PRAGMA table_info(iocs)")}
    missing = [name for name in _IOC_COLUMNS if name not in existing]
    for name in missing:
        connection.execute(f"ALTER TABLE iocs ADD COLUMN {name} {_IOC_COLUMNS[name]}")
    connection.execute(SOURCE_SCHEMA)
    if missing:
        # Rows that predate the upgrade have no history; stamp them now and
        # record their single known source so the new tables are consistent.
        now = to_iso(utcnow())
        connection.execute(
            "UPDATE iocs SET first_seen=COALESCE(first_seen,?), "
            "last_seen=COALESCE(last_seen,?)",
            (now, now),
        )
        connection.execute(
            "INSERT OR IGNORE INTO ioc_sources"
            "(type,value,source,first_seen,last_seen,observations) "
            "SELECT type,value,source,first_seen,last_seen,observations FROM iocs"
        )


# ---------------------------------------------------------------------------
# Normalisation and validation
# ---------------------------------------------------------------------------

_DOMAIN_BAD_CHARS = re.compile(r"[\s/:@]")
_HEX = re.compile(r"[0-9a-f]+")


def canonicalise_value(kind: str, value: str) -> str:
    """Validate and canonicalise one indicator value for its type.

    Raises :class:`ValueError` with a human-readable reason when the value does
    not belong to the declared type.
    """

    if kind == "ip":
        return _canonical_ip(value)
    if kind == "domain":
        return _canonical_domain(value)
    if kind == "hash":
        return _canonical_hash(value)
    if kind == "url":
        return _canonical_url(value)
    raise ValueError(f"Unsupported IOC type: {kind!r}")


def _canonical_ip(value: str) -> str:
    """Canonicalise an IPv4 or IPv6 address, or a CIDR range."""

    text = value.strip()
    if not text:
        raise ValueError("IP value cannot be empty")
    try:
        if "/" in text:
            return str(ipaddress.ip_network(text, strict=False))
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise ValueError(
            f"not a valid IP address or CIDR range: {value!r}"
        ) from exc


def _canonical_domain(value: str) -> str:
    """Lowercase a domain and strip a trailing dot.

    The check is deliberately loose: it rejects whitespace, a slash, a colon, an
    at-sign, an empty label or an over-long name, but it does not attempt full
    RFC 1035 validation, so unusual-but-real feed entries survive.
    """

    text = value.strip().lower().rstrip(".")
    if not text:
        raise ValueError("domain value cannot be empty")
    if len(text) > 253:
        raise ValueError(f"domain is longer than 253 characters: {value!r}")
    if _DOMAIN_BAD_CHARS.search(text):
        raise ValueError(f"not a valid domain name: {value!r}")
    if any(not label or len(label) > 63 for label in text.split(".")):
        raise ValueError(f"not a valid domain name: {value!r}")
    return text


def _canonical_hash(value: str) -> str:
    """Lowercase a hash and check its length matches a known algorithm."""

    text = value.strip().lower()
    if not text:
        raise ValueError("hash value cannot be empty")
    if not _HEX.fullmatch(text):
        raise ValueError(f"not a hexadecimal hash: {value!r}")
    if len(text) not in HASH_ALGORITHMS:
        known = ", ".join(str(length) for length in sorted(HASH_ALGORITHMS))
        raise ValueError(
            f"hash length {len(text)} is not a known algorithm (hex lengths {known})"
        )
    return text


def _canonical_url(value: str) -> str:
    """Lowercase the scheme and host of a URL and drop a trailing slash."""

    text = value.strip()
    if not text:
        raise ValueError("URL value cannot be empty")
    if re.search(r"\s", text):
        raise ValueError(f"not a valid URL: {value!r}")
    parts = urllib.parse.urlsplit(text)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"not a valid URL: {value!r}")
    path = parts.path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return urllib.parse.urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), path, parts.query, parts.fragment)
    )


def normalise_row(
    row: dict[str, str], default_source: str = "local"
) -> tuple[str, str, str]:
    """Clean one IOC row before saving it.

    Trims the fields, supplies a default source, rejects non-text fields and an
    unknown type, and canonicalises the value for its type.
    """

    for field in ("type", "value", "source"):
        if field in row and not isinstance(row[field], str):
            raise ValueError(f"IOC {field} must be text")
    kind = row.get("type", "").strip().lower()
    value = row.get("value", "").strip()
    source = row.get("source", default_source).strip() or default_source

    if kind not in VALID_TYPES:
        raise ValueError(f"Unsupported IOC type: {kind!r}")
    if not value:
        raise ValueError("IOC value cannot be empty")

    return kind, canonicalise_value(kind, value), source


# ---------------------------------------------------------------------------
# Reading feeds
# ---------------------------------------------------------------------------


def read_utf8_text(path: Path) -> str:
    """Read a feed as UTF-8 text, naming the file when decoding fails."""

    try:
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path.name} is not valid UTF-8 text: {exc}") from exc


def _looks_like_json(text: str, name: str) -> bool:
    """Decide whether a feed is JSON, by extension or by its first character."""

    lowered = name.lower()
    if lowered.endswith(".json"):
        return True
    if lowered.endswith(".csv"):
        return False
    return text.lstrip()[:1] in ("[", "{")


def _add_row(
    result: FeedResult, row: object, name: str, default_source: str
) -> None:
    """Normalise one feed row into the result, or record why it was skipped."""

    if not isinstance(row, dict):
        result.skipped.append(Skipped(name, "feed row is not an object", repr(row)[:80]))
        return
    try:
        kind, value, source = normalise_row(row, default_source)
    except ValueError as exc:
        raw = row.get("value")
        result.skipped.append(Skipped(name, str(exc), str(raw)[:80]))
        return
    result.indicators.append((kind, value, source))


def parse_feed_text(
    text: str, name: str = "feed", default_source: str = "local"
) -> FeedResult:
    """Parse CSV or JSON text into indicators and rejected rows.

    Structural problems (a bad JSON document, a missing CSV column, an oversized
    field) raise :class:`ValueError`, because they mean the whole feed is wrong.
    A single malformed indicator is skipped and counted instead.
    """

    result = FeedResult()

    if _looks_like_json(text, name):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{name} is not valid JSON: {exc}") from exc
        if not isinstance(data, list):
            raise ValueError(f"{name}: JSON feed must be a list")
        for item in data:
            _add_row(result, item, name, default_source)
        return result

    try:
        reader = csv.DictReader(io.StringIO(text))
        missing = [
            column
            for column in ("type", "value")
            if column not in (reader.fieldnames or ())
        ]
        if missing:
            raise ValueError(
                f"{name}: CSV feed is missing required column(s): {', '.join(missing)}"
            )
        for row in reader:
            _add_row(result, row, name, default_source)
    except csv.Error as exc:
        raise ValueError(f"{name}: could not parse CSV: {exc}") from exc
    return result


def read_feed(
    path: Path, default_source: str = "local"
) -> list[tuple[str, str, str]]:
    """Read IOC rows from a local JSON or CSV feed file."""

    return parse_feed_text(
        read_utf8_text(path), path.name, default_source
    ).indicators


def fetch_feed(url: str, timeout: float = DEFAULT_HTTP_TIMEOUT) -> str:
    """Download a feed over HTTP, naming the URL when it cannot be retrieved."""

    request = urllib.request.Request(
        url, headers={"User-Agent": "threat-intelligence-aggregator/1.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read()
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError) as exc:
        raise FeedFetchError(f"could not retrieve {url}: {exc}") from exc
    try:
        return payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{url} is not valid UTF-8 text: {exc}") from exc


def load_feed_file(
    path: Path, default_source: str | None = None
) -> FeedResult:
    """Read a feed file, tagging rows with the file name when they have none."""

    label = default_source or path.name
    return parse_feed_text(read_utf8_text(path), path.name, label)


def load_feed_url(
    url: str,
    timeout: float = DEFAULT_HTTP_TIMEOUT,
    default_source: str | None = None,
) -> FeedResult:
    """Fetch a feed URL, tagging rows with the URL when they have no source."""

    label = default_source or url
    name = urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1] or "feed"
    return parse_feed_text(fetch_feed(url, timeout), name, label)


def discover_feed_dir(directory: Path) -> list[Path]:
    """List the CSV and JSON feeds in a directory, in a stable order."""

    path = Path(directory)
    if not path.is_dir():
        raise ValueError(f"{path} is not a directory")
    return sorted(
        entry
        for entry in path.iterdir()
        if entry.is_file() and entry.suffix.lower() in {".csv", ".json"}
    )


# ---------------------------------------------------------------------------
# Import, merge and confidence
# ---------------------------------------------------------------------------


def _refresh_confidence(
    connection: sqlite3.Connection, kind: str, value: str, now: datetime
) -> None:
    """Recompute the stored confidence for one indicator."""

    sources = connection.execute(
        "SELECT COUNT(*) FROM ioc_sources WHERE type=? AND value=?", (kind, value)
    ).fetchone()[0]
    last_seen_row = connection.execute(
        "SELECT last_seen FROM iocs WHERE type=? AND value=?", (kind, value)
    ).fetchone()
    last_seen = parse_iso(last_seen_row[0]) if last_seen_row else None
    confidence = compute_confidence(sources, last_seen, now)
    connection.execute(
        "UPDATE iocs SET confidence=? WHERE type=? AND value=?",
        (confidence, kind, value),
    )


def import_indicators(
    db_path: Path,
    indicators: Iterable[tuple[str, str, str]],
    now: datetime | None = None,
) -> ImportResult:
    """Merge indicators into the store, tracking every reporting source.

    The same indicator from several feeds becomes one ``iocs`` row whose
    ``ioc_sources`` rows name each feed. ``first_seen`` is kept, ``last_seen``
    moves forward, the observation count rises, and confidence is recomputed.
    """

    now = now or utcnow()
    stamp = to_iso(now)
    result = ImportResult()

    with closing(get_connection(db_path)) as connection, connection:
        for kind, value, source in indicators:
            try:
                canonical = canonicalise_value(kind, value)
            except ValueError as exc:
                result.skipped.append(Skipped(source, str(exc), str(value)[:80]))
                continue
            kind, value = kind.strip().lower(), canonical
            source = (source or "").strip() or "local"

            existing = connection.execute(
                "SELECT observations FROM iocs WHERE type=? AND value=?",
                (kind, value),
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO iocs"
                    "(type,value,source,first_seen,last_seen,observations,confidence) "
                    "VALUES (?,?,?,?,?,1,0)",
                    (kind, value, source, stamp, stamp),
                )
                result.new += 1
            else:
                connection.execute(
                    "UPDATE iocs SET last_seen=?, observations=observations+1 "
                    "WHERE type=? AND value=?",
                    (stamp, kind, value),
                )
                result.updated += 1

            seen = connection.execute(
                "SELECT observations FROM ioc_sources "
                "WHERE type=? AND value=? AND source=?",
                (kind, value, source),
            ).fetchone()
            if seen is None:
                connection.execute(
                    "INSERT INTO ioc_sources"
                    "(type,value,source,first_seen,last_seen,observations) "
                    "VALUES (?,?,?,?,?,1)",
                    (kind, value, source, stamp, stamp),
                )
            else:
                connection.execute(
                    "UPDATE ioc_sources SET last_seen=?, observations=observations+1 "
                    "WHERE type=? AND value=? AND source=?",
                    (stamp, kind, value, source),
                )

            _refresh_confidence(connection, kind, value, now)

    return result


def import_iocs(
    db_path: Path, rows: Iterable[tuple[str, str, str]]
) -> int:
    """Insert new indicators and skip duplicates; return the number added."""

    return import_indicators(db_path, list(rows)).new


# ---------------------------------------------------------------------------
# Search, stats, expiry and export
# ---------------------------------------------------------------------------

def _escape_like(value: str) -> str:
    """Escape SQL wildcard characters in search text."""

    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def search_iocs(db_path: Path, term: str) -> list[tuple[str, str, str]]:
    """Search stored indicator values, returning type, value and source."""

    pattern = f"%{_escape_like(term)}%"
    with closing(get_connection(db_path)) as connection, connection:
        rows = connection.execute(
            "SELECT type,value,source FROM iocs "
            "WHERE value LIKE ? ESCAPE '\\' ORDER BY type,value",
            (pattern,),
        ).fetchall()
    return [(row[0], row[1], row[2]) for row in rows]


def _query_hits(
    db_path: Path, pattern: str, now: datetime
) -> list[SearchHit]:
    """Load indicators matching a LIKE pattern, with their source list and age."""

    with closing(get_connection(db_path)) as connection, connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT type,value,source,first_seen,last_seen,observations "
            "FROM iocs WHERE value LIKE ? ESCAPE '\\' ORDER BY type,value",
            (pattern,),
        ).fetchall()
        hits: list[SearchHit] = []
        for row in rows:
            sources = [
                source_row[0]
                for source_row in connection.execute(
                    "SELECT source FROM ioc_sources WHERE type=? AND value=? "
                    "ORDER BY source",
                    (row["type"], row["value"]),
                )
            ]
            if not sources:
                sources = [row["source"]]
            last_seen = parse_iso(row["last_seen"])
            age = age_days(last_seen, now)
            hits.append(
                SearchHit(
                    type=row["type"],
                    value=row["value"],
                    source=row["source"],
                    sources=sources,
                    first_seen=row["first_seen"],
                    last_seen=row["last_seen"],
                    observations=row["observations"],
                    confidence=compute_confidence(len(sources), last_seen, now),
                    age_days=age,
                    age_band=age_band(age),
                )
            )
    return hits


def search_indicators(
    db_path: Path, term: str, now: datetime | None = None
) -> list[SearchHit]:
    """Search every indicator type, reporting sources and age for each hit."""

    now = now or utcnow()
    return _query_hits(db_path, f"%{_escape_like(term)}%", now)


def list_indicators(
    db_path: Path, now: datetime | None = None
) -> list[SearchHit]:
    """Every stored indicator, newest metadata included."""

    now = now or utcnow()
    return _query_hits(db_path, "%", now)


def expire_iocs(
    db_path: Path, expire_days: int, now: datetime | None = None
) -> list[ExpiredIndicator]:
    """Delete indicators not seen within the window and report what went."""

    now = now or utcnow()
    cutoff = to_iso(now - timedelta(days=expire_days))
    with closing(get_connection(db_path)) as connection, connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT type,value,source,last_seen FROM iocs "
            "WHERE last_seen IS NOT NULL AND last_seen < ? ORDER BY type,value",
            (cutoff,),
        ).fetchall()
        for row in rows:
            connection.execute(
                "DELETE FROM iocs WHERE type=? AND value=?",
                (row["type"], row["value"]),
            )
            connection.execute(
                "DELETE FROM ioc_sources WHERE type=? AND value=?",
                (row["type"], row["value"]),
            )
        return [
            ExpiredIndicator(row["type"], row["value"], row["source"], row["last_seen"])
            for row in rows
        ]


def collect_stats(db_path: Path, now: datetime | None = None) -> Stats:
    """Count indicators by type, by reporting source and by age band."""

    now = now or utcnow()
    with closing(get_connection(db_path)) as connection, connection:
        connection.row_factory = sqlite3.Row
        total = connection.execute("SELECT COUNT(*) AS n FROM iocs").fetchone()["n"]
        by_type = [
            (row["type"], row["n"])
            for row in connection.execute(
                "SELECT type, COUNT(*) AS n FROM iocs GROUP BY type "
                "ORDER BY n DESC, type"
            )
        ]
        by_source = [
            (row["source"], row["n"])
            for row in connection.execute(
                "SELECT source, COUNT(*) AS n FROM ioc_sources GROUP BY source "
                "ORDER BY n DESC, source"
            )
        ]
        bands = {label: 0 for label in AGE_BAND_LABELS}
        for row in connection.execute("SELECT last_seen FROM iocs"):
            bands[age_band(age_days(parse_iso(row["last_seen"]), now))] += 1
    by_age = [(label, bands[label]) for label in AGE_BAND_LABELS]
    return Stats(total, by_type, by_source, by_age)


def export_iocs(
    db_path: Path,
    destination: Path,
    fmt: str | None = None,
    now: datetime | None = None,
) -> int:
    """Write the store to CSV or JSON; return the number of indicators written."""

    destination = Path(destination)
    fmt = (fmt or destination.suffix.lstrip(".")).lower()
    if fmt not in {"csv", "json"}:
        raise ValueError(
            f"unsupported export format: {fmt!r} (use csv or json)"
        )

    hits = list_indicators(db_path, now)
    records = [
        {
            "type": hit.type,
            "value": hit.value,
            "source": hit.source,
            "sources": ";".join(hit.sources),
            "first_seen": hit.first_seen or "",
            "last_seen": hit.last_seen or "",
            "observations": hit.observations,
            "confidence": hit.confidence,
            "age_days": round(hit.age_days, 2) if hit.age_days is not None else "",
            "age_band": hit.age_band,
        }
        for hit in hits
    ]

    if fmt == "json":
        destination.write_text(
            json.dumps(records, indent=2) + "\n", encoding="utf-8"
        )
    else:
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=EXPORT_FIELDS)
            writer.writeheader()
            writer.writerows(records)
    return len(records)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def _summarise_skips(skipped: list[Skipped]) -> str:
    """Group skipped rows by reason for a one-line report."""

    counts = Counter(item.reason for item in skipped)
    parts = [f"{count} x {reason}" for reason, count in counts.most_common(5)]
    return "; ".join(parts)


def _run_imports(
    db_path: Path, feed_results: Iterable[FeedResult], now: datetime | None
) -> ImportResult:
    """Import several parsed feeds into one store."""

    imported = ImportResult()
    for result in feed_results:
        imported.skipped.extend(result.skipped)
        outcome = import_indicators(db_path, result.indicators, now=now)
        imported.new += outcome.new
        imported.updated += outcome.updated
        imported.skipped.extend(outcome.skipped)
    return imported


def main(argv: list[str] | None = None) -> None:
    """Import feeds and/or search, summarise, export or expire the store."""

    parser = argparse.ArgumentParser(
        description="Aggregate, store and search threat-intelligence feeds."
    )
    parser.add_argument("--db", type=Path, default=Path("threat_intel.db"))
    parser.add_argument(
        "--feed",
        type=Path,
        action="append",
        default=[],
        help="a CSV or JSON feed file (repeatable)",
    )
    parser.add_argument(
        "--feed-url",
        action="append",
        default=[],
        help="a feed URL fetched over HTTP (repeatable)",
    )
    parser.add_argument(
        "--feed-dir", type=Path, help="a directory of .csv and .json feeds"
    )
    parser.add_argument(
        "--http-timeout",
        type=float,
        default=DEFAULT_HTTP_TIMEOUT,
        help="seconds to wait for a feed URL",
    )
    parser.add_argument(
        "--expire-days",
        type=int,
        help="prune indicators not seen within this many days",
    )
    parser.add_argument("--search")
    parser.add_argument("--stats", action="store_true")
    parser.add_argument("--export", type=Path)
    parser.add_argument("--export-format", choices=["csv", "json"])
    args = parser.parse_args(argv)

    feeds: list[Path] = list(args.feed)
    if args.feed_dir:
        feeds.extend(discover_feed_dir(args.feed_dir))

    doing = bool(
        feeds
        or args.feed_url
        or args.search is not None
        or args.stats
        or args.export
        or args.expire_days is not None
    )
    if not doing:
        parser.error(
            "Use --feed and/or --search "
            "(also --feed-url, --feed-dir, --stats, --export, --expire-days)"
        )
    if args.search is not None and not args.search.strip():
        # An empty --search used to be reported as if no option had been given.
        parser.error("Search text must not be empty")

    if feeds or args.feed_url:
        feed_results = [load_feed_file(path) for path in feeds]
        feed_results.extend(
            load_feed_url(url, args.http_timeout) for url in args.feed_url
        )
        imported = _run_imports(args.db, feed_results, now=None)
        print(
            f"Imported {imported.new} new indicators "
            f"({imported.updated} updated)."
        )
        if imported.skipped:
            count = len(imported.skipped)
            noun = "entry" if count == 1 else "entries"
            print(
                f"Skipped {count} malformed {noun}: "
                f"{_summarise_skips(imported.skipped)}."
            )

    if args.expire_days is not None:
        pruned = expire_iocs(args.db, args.expire_days)
        print(
            f"Pruned {len(pruned)} stale indicators "
            f"(not seen in {args.expire_days} days)."
        )
        for item in pruned:
            print(f"  {item.type:7} {item.value}")

    if args.search:
        hits = search_indicators(args.db, args.search)
        if not hits:
            print("No matching IOCs found.")
        else:
            print(f"{'type':7} {'value':40} {'sources':30} {'age':>8}  confidence")
        for hit in hits:
            sources = ", ".join(hit.sources)
            age = "unknown" if hit.age_days is None else f"{hit.age_days:.0f}d"
            print(
                f"{hit.type:7} {hit.value:40} {sources:30} {age:>8}  {hit.confidence:.2f}"
            )

    if args.stats:
        stats = collect_stats(args.db)
        print(f"Total indicators: {stats.total}")
        print("By type:")
        for name, count in stats.by_type:
            print(f"  {name:8} {count}")
        print("By source:")
        for name, count in stats.by_source:
            print(f"  {name:30} {count}")
        print("By age:")
        for name, count in stats.by_age:
            print(f"  {name:8} {count}")

    if args.export:
        written = export_iocs(args.db, args.export, args.export_format)
        print(f"Exported {written} indicators to {args.export}.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, sqlite3.Error, csv.Error, RecursionError) as exc:
        raise SystemExit(f"Feed operation failed: {exc}") from exc
