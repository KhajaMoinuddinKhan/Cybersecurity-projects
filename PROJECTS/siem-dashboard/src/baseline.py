"""Per-host behavioural baselining: what is normal for a host, not just a match.

The console can say an event matches a rule. It cannot say whether that event is
unusual *for this host* -- a workstation that fires one failed logon an hour and
a server that fires none look identical to a pattern match. This module adds the
missing half: for each host and each key (a detection rule, or an event channel)
it records how many events that key produced per hour over a window, and from
those hourly counts it stores a mean and a standard deviation.
:func:`detect_deviations` then compares the most recent window against that
baseline and reports a key whose current count sits further out than a caller-set
number of standard deviations.

What a baseline is
------------------
For each ``(host, key_kind, key_value)`` the stored row describes the
distribution of hourly event counts for that key on that host over the window.
``key_kind`` is ``'rule'`` for a detection rule (``live_events.rule_id``) or
``'event_type'`` for an event channel (``live_events.channel``; this store has no
separate column for the canonical ``event_type`` field, so the channel is the
event type that is bucketed). A host is identified by the ``live_events.host``
column value, matching how the triage module identifies a host.

Empty buckets
-------------
Only hours in which the key actually produced at least one event become samples.
Hours with no events are **excluded**, not counted as zero. The choice matters: a
workstation that is switched off at night, or that only logs activity during the
working day, would otherwise have its quiet hours counted as genuine zeros, which
would drag the mean down and inflate the standard deviation. The "expected" value
would then describe the host's uptime rather than its behaviour, and ordinary
daytime activity would sit far out on the tail and be flagged. Excluding empty
hours makes the baseline describe the intensity of a key during the hours the host
was actually producing it. The cost is honest and real: an hour in which a key
starts firing where it never used to is invisible here, because an empty hour is
not a sample, so a key that fires for the first time in a previously silent hour
is not, by itself, a deviation from a mean.

Standard deviation
------------------
The stored standard deviation is the *population* standard deviation of the
observed hourly counts (divided by N, not N-1): the window is treated as the whole
record of the host's behaviour, not as a sample drawn from a larger population.

The minimum-sample guard
------------------------
A mean and a standard deviation computed from a handful of hours are noise. A key
with fewer than ``min_samples`` non-empty hourly buckets is never stored by
:func:`build_baseline` and is never judged by :func:`detect_deviations`; it is
reported as having insufficient history instead. ``min_samples`` defaults to 24,
so by default a key needs at least a day's worth of active hours before it can
produce a deviation. This is the guard that stops three samples from inventing an
alert.

Honest limits
-------------
This is a simple per-key statistical baseline and nothing more:

* It knows nothing about correlation between keys. Ten rules each one event below
  their own threshold is not seen as one incident; a burst spread thinly across
  many keys is invisible.
* It cannot see an attack that stays inside normal volume. A key that always
  fires a hundred times an hour has a high mean, and an attacker who stays under
  that is never reported. Baselining measures volume, not intent.
* A host that is quiet for most of the week produces a low-volume baseline, so
  ordinary daytime activity can sit above it and be flagged. The default window
  and ``min_samples`` limit how often that happens, but they do not remove it.
* It counts events, not severity or content. A key whose counts are normal but
  whose events have changed meaning is not flagged.
* A key with a constant count (standard deviation zero) has no finite sigma
  distance; :func:`detect_deviations` flags any count above the mean as ``High``
  and reports ``sigma_distance`` as ``None`` rather than dividing by zero.

Nothing here opens a database of its own: every function takes a live
``sqlite3.Connection`` and the caller invokes :func:`ensure_schema` once. Every
write commits on the connection it is given.
"""
from __future__ import annotations

import math
import sqlite3
from datetime import datetime, timezone
from typing import Any

# The two kinds of key a baseline can be built for.
KEY_KINDS = ("rule", "event_type")

# Defaults, named so a caller can see what "no argument" means.
DEFAULT_WINDOW_HOURS = 168  # one week
DEFAULT_MIN_SAMPLES = 24  # a day's worth of active hours
DEFAULT_WINDOW_MINUTES = 60
DEFAULT_SIGMA = 3.0

# Severity is a fixed function of the sigma distance, so the same observation is
# graded the same way whatever ``sigma`` threshold a caller chose to flag on.
_SEVERITY_HIGH = 5.0
_SEVERITY_MEDIUM = 4.0

SCHEMA = """
CREATE TABLE IF NOT EXISTS baselines (
    host TEXT NOT NULL,
    key_kind TEXT NOT NULL CHECK (key_kind IN ('rule','event_type')),
    key_value TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    mean REAL NOT NULL,
    stddev REAL NOT NULL,
    minimum INTEGER NOT NULL,
    maximum INTEGER NOT NULL,
    first_observed TEXT NOT NULL,
    last_observed TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (host, key_kind, key_value)
)
"""

INDEXES = (
    "CREATE INDEX IF NOT EXISTS ix_baselines_kind ON baselines(key_kind, key_value)",
)

_SELECT = (
    "SELECT host,key_kind,key_value,sample_count,mean,stddev,minimum,maximum,"
    "first_observed,last_observed,updated_at FROM baselines"
)

_UPSERT = (
    "INSERT INTO baselines(host,key_kind,key_value,sample_count,mean,stddev,minimum,"
    "maximum,first_observed,last_observed,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
    "ON CONFLICT(host,key_kind,key_value) DO UPDATE SET "
    "sample_count = excluded.sample_count, mean = excluded.mean, "
    "stddev = excluded.stddev, minimum = excluded.minimum, maximum = excluded.maximum, "
    "first_observed = excluded.first_observed, last_observed = excluded.last_observed, "
    "updated_at = excluded.updated_at"
)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create this module's table and index if they are not already there.

    Idempotent: callers may invoke it on every request. It also points the
    connection at ``sqlite3.Row`` when nothing else has, so every read below can
    address columns by name.
    """

    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row
    conn.execute(SCHEMA)
    for statement in INDEXES:
        conn.execute(statement)
    conn.commit()


def _now() -> str:
    """The current time in the same UTC form the event store uses."""

    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    """Run a query, guaranteeing rows can be addressed by column name."""

    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row
    return conn.execute(sql, params).fetchall()


def _positive_int(value: Any, field: str) -> int:
    """A whole number greater than zero, or a ValueError naming the field."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be a whole number greater than zero")
    if value <= 0:
        raise ValueError(f"{field} must be a whole number greater than zero")
    return value


def _positive_float(value: Any, field: str) -> float:
    """A number greater than zero, or a ValueError naming the field."""

    if isinstance(value, bool):
        raise ValueError(f"{field} must be a number greater than zero")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be a number greater than zero") from None
    if not math.isfinite(number) or number <= 0:
        raise ValueError(f"{field} must be a number greater than zero")
    return number


def _normalise_kind(value: Any) -> str:
    """Return a supported key kind, or raise ValueError."""

    candidate = str(value or "").strip().lower()
    if candidate not in KEY_KINDS:
        raise ValueError(
            f"Unsupported key kind {value!r}. Expected one of: {', '.join(KEY_KINDS)}."
        )
    return candidate


def _require_host(value: Any, field: str) -> str:
    """A non-empty host string, or a ValueError naming the field."""

    text = "" if value is None else str(value).strip()
    if not text:
        raise ValueError(f"{field} must be a non-empty string when given")
    return text


def _severity_for(distance: float | None) -> str:
    """Grade a deviation by its sigma distance.

    ``None`` means the baseline has zero variance, so the distance is undefined
    and any increase is treated as the most serious grade. Otherwise a fixed
    scale is used so the grade does not move when a caller changes ``sigma``.
    """

    if distance is None:
        return "High"
    if distance >= _SEVERITY_HIGH:
        return "High"
    if distance >= _SEVERITY_MEDIUM:
        return "Medium"
    return "Low"


def _baseline_dict(row: sqlite3.Row) -> dict[str, Any]:
    """One stored baseline as a plain, JSON-serialisable dict."""

    minimum = int(row["minimum"])
    maximum = int(row["maximum"])
    kind = str(row["key_kind"])
    value = str(row["key_value"])
    return {
        "host": str(row["host"]),
        "key_kind": kind,
        "key_value": value,
        "key": f"{kind}:{value}",
        "sample_count": int(row["sample_count"]),
        "mean": float(row["mean"]),
        "stddev": float(row["stddev"]),
        "minimum": minimum,
        "maximum": maximum,
        "range": maximum - minimum,
        "first_observed": str(row["first_observed"]),
        "last_observed": str(row["last_observed"]),
        "updated_at": str(row["updated_at"]),
    }


def bucket_counts(conn: sqlite3.Connection, hours: int = DEFAULT_WINDOW_HOURS) -> list[dict[str, Any]]:
    """Count events per hour per host per key over the last ``hours`` hours.

    Returns one dict per non-empty bucket: ``host``, ``key_kind``, ``key_value``,
    ``bucket`` (the hour's start as ``YYYY-MM-DD HH:00:00``) and ``count``. Two
    keys are produced from the same events: ``key_kind='rule'`` counts by
    ``rule_id`` (events with an empty rule id are not a rule and are skipped) and
    ``key_kind='event_type'`` counts by ``channel``. All events are counted, not
    only alerts, because a baseline describes behaviour rather than detections.

    The grouping and the hour truncation are done by SQLite's ``strftime`` and
    ``datetime`` functions in ``GROUP BY`` queries; the Python side only shapes
    the rows. Buckets with no events do not exist here at all -- see the module
    docstring for why empty hours are excluded rather than counted as zero.
    """

    resolved_hours = _positive_int(hours, "hours")
    cutoff = f"-{resolved_hours} hours"
    results: list[dict[str, Any]] = []

    rule_rows = _rows(
        conn,
        "SELECT host, strftime('%Y-%m-%d %H:00:00', timestamp) AS bucket, "
        "rule_id AS key_value, COUNT(*) AS count "
        "FROM live_events "
        "WHERE timestamp >= datetime('now', ?) AND rule_id != '' "
        "GROUP BY host, strftime('%Y-%m-%d %H:00:00', timestamp), rule_id",
        (cutoff,),
    )
    for row in rule_rows:
        results.append(
            {
                "host": str(row["host"]),
                "key_kind": "rule",
                "key_value": str(row["key_value"]),
                "bucket": str(row["bucket"]),
                "count": int(row["count"]),
            }
        )

    type_rows = _rows(
        conn,
        "SELECT host, strftime('%Y-%m-%d %H:00:00', timestamp) AS bucket, "
        "channel AS key_value, COUNT(*) AS count "
        "FROM live_events "
        "WHERE timestamp >= datetime('now', ?) AND channel != '' "
        "GROUP BY host, strftime('%Y-%m-%d %H:00:00', timestamp), channel",
        (cutoff,),
    )
    for row in type_rows:
        results.append(
            {
                "host": str(row["host"]),
                "key_kind": "event_type",
                "key_value": str(row["key_value"]),
                "bucket": str(row["bucket"]),
                "count": int(row["count"]),
            }
        )

    results.sort(key=lambda item: (item["host"], item["key_kind"], item["key_value"], item["bucket"]))
    return results


def build_baseline(
    conn: sqlite3.Connection,
    hours: int = DEFAULT_WINDOW_HOURS,
    min_samples: int = DEFAULT_MIN_SAMPLES,
) -> dict[str, Any]:
    """Compute and store a mean, standard deviation and range per key.

    Reads :func:`bucket_counts` over ``hours``, groups the buckets by
    ``(host, key_kind, key_value)`` and, for every key with at least
    ``min_samples`` non-empty buckets, stores the population mean and standard
    deviation, the minimum and maximum hourly count, the first and last bucket
    timestamp and the update time. A key with fewer buckets is not stored: it is
    counted in ``skipped`` instead, so the caller can see how much of the data
    was too thin to judge.

    Re-running updates existing rows in place. It does not delete a baseline
    whose key has since disappeared from the window; use :func:`clear_baseline`
    to reset. Returns ``built``, ``skipped``, ``window_hours`` and
    ``min_samples``.
    """

    resolved_hours = _positive_int(hours, "hours")
    resolved_min = _positive_int(min_samples, "min_samples")
    ensure_schema(conn)

    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for bucket in bucket_counts(conn, hours=resolved_hours):
        identity = (bucket["host"], bucket["key_kind"], bucket["key_value"])
        groups.setdefault(identity, []).append(bucket)

    built = 0
    skipped = 0
    now = _now()
    for (host, kind, value), rows in groups.items():
        counts = [int(row["count"]) for row in rows]
        if len(counts) < resolved_min:
            skipped += 1
            continue

        sample_count = len(counts)
        mean = sum(counts) / sample_count
        variance = sum((count - mean) ** 2 for count in counts) / sample_count
        stddev = math.sqrt(variance)
        buckets = sorted(str(row["bucket"]) for row in rows)

        conn.execute(
            _UPSERT,
            (
                host,
                kind,
                value,
                sample_count,
                mean,
                stddev,
                min(counts),
                max(counts),
                buckets[0],
                buckets[-1],
                now,
            ),
        )
        built += 1

    conn.commit()
    return {
        "built": built,
        "skipped": skipped,
        "window_hours": resolved_hours,
        "min_samples": resolved_min,
    }


def list_baselines(
    conn: sqlite3.Connection,
    host: str | None = None,
    kind: str | None = None,
) -> list[dict[str, Any]]:
    """Every stored baseline, optionally filtered by host and key kind.

    ``kind`` must be ``'rule'`` or ``'event_type'``. Ordered by host, then kind,
    then key so the result is stable.
    """

    ensure_schema(conn)
    clauses: list[str] = []
    params: list[Any] = []
    if host is not None:
        clauses.append("host = ?")
        params.append(_require_host(host, "host"))
    if kind is not None:
        clauses.append("key_kind = ?")
        params.append(_normalise_kind(kind))

    sql = _SELECT
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY host ASC, key_kind ASC, key_value ASC"
    return [_baseline_dict(row) for row in _rows(conn, sql, tuple(params))]


def _window_counts(conn: sqlite3.Connection, minutes: int) -> dict[tuple[str, str, str], int]:
    """Event counts per host and key inside the last ``minutes`` minutes.

    The same two key kinds :func:`bucket_counts` uses, but over a minute window
    and with no hour bucketing, since :func:`detect_deviations` compares the
    whole recent window against the hourly baseline. A key with no events in the
    window is simply absent, and is read as zero by the caller.
    """

    cutoff = f"-{minutes} minutes"
    counts: dict[tuple[str, str, str], int] = {}
    for kind, column in (("rule", "rule_id"), ("event_type", "channel")):
        rows = _rows(
            conn,
            f"SELECT host, {column} AS key_value, COUNT(*) AS count FROM live_events "
            f"WHERE timestamp >= datetime('now', ?) AND {column} != '' "
            f"GROUP BY host, {column}",
            (cutoff,),
        )
        for row in rows:
            counts[(str(row["host"]), kind, str(row["key_value"]))] = int(row["count"])
    return counts


def detect_deviations(
    conn: sqlite3.Connection,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    sigma: float = DEFAULT_SIGMA,
    min_samples: int = DEFAULT_MIN_SAMPLES,
) -> list[dict[str, Any]]:
    """Find baselined keys whose recent count is far above their own baseline.

    For every stored baseline with at least ``min_samples`` samples, the count of
    events for that key in the last ``window_minutes`` is compared against
    ``mean + sigma * stddev``. A key whose observed count exceeds that threshold
    is returned with the observed count, the expected count (the mean), the
    standard deviation, the sigma distance ``(observed - mean) / stddev``, the
    host, the key and a severity graded from the sigma distance. Results are
    ordered by sigma distance, furthest first.

    A key with fewer than ``min_samples`` samples is never judged: the standard
    deviation of a few samples is noise, so such a key is absent from the result
    rather than reported as a weak deviation. A key whose baseline has zero
    variance is reported with ``sigma_distance`` of ``None`` and severity
    ``High`` when its observed count exceeds the mean (see the module docstring).
    """

    resolved_minutes = _positive_int(window_minutes, "window_minutes")
    resolved_min = _positive_int(min_samples, "min_samples")
    resolved_sigma = _positive_float(sigma, "sigma")
    ensure_schema(conn)

    baselines = _rows(
        conn,
        _SELECT + " WHERE sample_count >= ?",
        (resolved_min,),
    )
    observed = _window_counts(conn, resolved_minutes)

    deviations: list[dict[str, Any]] = []
    for row in baselines:
        host = str(row["host"])
        kind = str(row["key_kind"])
        value = str(row["key_value"])
        count = observed.get((host, kind, value), 0)

        mean = float(row["mean"])
        stddev = float(row["stddev"])
        threshold = mean + resolved_sigma * stddev
        if count <= threshold:
            continue

        if stddev > 0:
            distance: float | None = (count - mean) / stddev
        else:
            distance = None

        deviations.append(
            {
                "host": host,
                "key_kind": kind,
                "key_value": value,
                "key": f"{kind}:{value}",
                "observed": int(count),
                "expected": mean,
                "stddev": stddev,
                "sigma_distance": distance,
                "severity": _severity_for(distance),
                "threshold": threshold,
                "sample_count": int(row["sample_count"]),
                "sigma": resolved_sigma,
                "window_minutes": resolved_minutes,
            }
        )

    deviations.sort(
        key=lambda item: item["sigma_distance"] if item["sigma_distance"] is not None else math.inf,
        reverse=True,
    )
    return deviations


def baseline_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    """Count what is baselined, across how many hosts, and what cannot be judged.

    ``baselined`` is the number of stored keys, ``hosts`` the number of distinct
    hosts they cover, and ``insufficient_history`` the number of keys seen in the
    current default window that have too few non-empty buckets to build a
    baseline from and are not already stored. ``observed_keys`` is every key seen
    in that window. ``min_samples`` and ``window_hours`` are the defaults used to
    decide, since this function takes no arguments.
    """

    ensure_schema(conn)
    stored = _rows(conn, "SELECT host, key_kind, key_value FROM baselines")
    baselined_keys = {(str(row["host"]), str(row["key_kind"]), str(row["key_value"])) for row in stored}
    hosts = {host for host, _kind, _value in baselined_keys}

    seen: dict[tuple[str, str, str], int] = {}
    for bucket in bucket_counts(conn, hours=DEFAULT_WINDOW_HOURS):
        identity = (bucket["host"], bucket["key_kind"], bucket["key_value"])
        seen[identity] = seen.get(identity, 0) + 1

    insufficient = sum(
        1
        for identity, sample_count in seen.items()
        if sample_count < DEFAULT_MIN_SAMPLES and identity not in baselined_keys
    )

    return {
        "baselined": len(baselined_keys),
        "hosts": len(hosts),
        "insufficient_history": insufficient,
        "observed_keys": len(seen),
        "min_samples": DEFAULT_MIN_SAMPLES,
        "window_hours": DEFAULT_WINDOW_HOURS,
    }


def clear_baseline(conn: sqlite3.Connection, host: str | None = None) -> dict[str, Any]:
    """Delete stored baselines, for one host or for every host.

    Returns the number of rows deleted and the host scope (``None`` when every
    host was cleared).
    """

    ensure_schema(conn)
    if host is None:
        cursor = conn.execute("DELETE FROM baselines")
        scope: str | None = None
    else:
        scope = _require_host(host, "host")
        cursor = conn.execute("DELETE FROM baselines WHERE host = ?", (scope,))
    conn.commit()
    return {"deleted": int(cursor.rowcount), "host": scope}
