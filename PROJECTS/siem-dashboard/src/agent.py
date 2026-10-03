"""Forward events from many machines to one SIEM server.

This is the collector agent. It reads events on the machine it runs on and
POSTs them to a central dashboard's ``/api/ingest`` endpoint, which is what
turns a single-host console into a multi-host one. Run one agent per machine::

    python -m src.agent --server https://siem.example --host-id web-01 --key TOKEN

What this module is, and what it is not
---------------------------------------
It is a simple forwarder, not an endpoint agent. There is no installer, no
service registration, no privilege separation and no tamper protection: anyone
who can edit this file, its arguments or its spool can change what the server
sees, and the agent runs with whatever rights the operator gave it. It does not
enrol, does not receive commands back from the server, and does not sign its
payloads. The bearer key proves *a* key was presented, not which machine sent a
batch.

The spool is plain text on disk
-------------------------------
When the server cannot be reached, unsent events are appended to a JSONL file
(the spool) so a network outage does not lose them. That file is ordinary
unencrypted text: anyone who can read it sees every event the agent failed to
ship, including any credentials that were in event messages. Put it somewhere
with the permissions you would give a log file, and treat it as sensitive.

Wire format (the contract the server is written against)
--------------------------------------------------------
``ship_batch`` POSTs to ``{server}/api/ingest`` with
``Authorization: Bearer <key>`` and ``Content-Type: application/json``. The
request body is exactly::

    {
      "host_id": "<the --host-id value>",
      "agent_version": "<this module's version string>",
      "platform": "<platform.system(), e.g. 'Windows'>",
      "events": [ <canonical event dict>, ... ]
    }

Each entry of ``events`` is a canonical event dict: the same shape
``windows_collector.windows_event_to_payload`` produces and the shape
``app.normalise_payload`` accepts. The keys a server can rely on are
``timestamp`` (ISO-8601), ``message`` (required, non-empty), ``severity``,
``channel``, ``provider``, ``event_id``, ``level``, ``username``, ``host``,
``source_ip``, ``source``, ``is_alert`` (bool), ``rule_name``, ``record_id``,
``raw_log`` (JSON string) and ``fields`` (mapping). The file source fills any
missing key with a neutral default rather than inventing a value.

The server must answer with ``2xx`` and a JSON object of this shape::

    {"accepted": <int>, "rejected": <int>, "errors": [<str>, ...]}

``accepted`` is the number of events the server stored. Anything that is not a
``2xx`` response, or a body that is not a JSON object, is treated as a failure:
``ship_batch`` raises :class:`ShipError` and the caller spools the batch.

The server endpoint itself is not implemented here; this module only defines
the client side of the contract above.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

from .windows_collector import CHANNELS, WindowsEventCollector

AGENT_VERSION = "0.1.0"

DEFAULT_INTERVAL = 30.0
DEFAULT_TIMEOUT = 10.0
DEFAULT_BATCH_SIZE = 500
DEFAULT_MAX_SPOOL_BYTES = 5 * 1024 * 1024  # 5 MB of plain-text spool.
DEFAULT_SPOOL_PATH = Path("siem-agent-spool.jsonl")

VALID_SOURCES = ("windows", "file")

# A collector is a zero-argument callable returning canonical event dicts. Tests
# inject a fake; the real ones are the Windows collector and the file tailer.
CollectorFn = Callable[[], list[dict[str, Any]]]

# A poster has the same signature as :func:`ship_batch`, so a test can swap in a
# fake that never touches the network.
PosterFn = Callable[[str, str, str, list[dict[str, Any]], float], dict[str, Any]]


class ShipError(RuntimeError):
    """A batch could not be delivered.

    Raised for a transport failure, a non-2xx response, or a response body that
    is not the documented JSON object. The caller's response is to spool the
    batch, so the distinction between these cases only matters for the message.
    """


# --------------------------------------------------------------------------- #
# Shipping
# --------------------------------------------------------------------------- #

def _platform_label() -> str:
    """The value sent in the body's ``platform`` field."""

    return platform.system() or os.name


def ship_batch(
    server: str,
    host_id: str,
    key: str,
    events: list[dict[str, Any]],
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """POST one batch to ``{server}/api/ingest`` and return the parsed response.

    Raises :class:`ShipError` on a transport failure, a non-2xx response, or a
    body that is not the documented JSON object. Raises ``ValueError`` when a
    required argument is missing. The body shape is documented in the module
    docstring; the server is written against it.
    """

    if not server or not str(server).strip():
        raise ValueError("server URL is required")
    if not host_id or not str(host_id).strip():
        raise ValueError("host_id is required")
    if not isinstance(events, list):
        raise ValueError("events must be a list of event dicts")

    body = {
        "host_id": str(host_id),
        "agent_version": AGENT_VERSION,
        "platform": _platform_label(),
        "events": events,
    }
    url = str(server).rstrip("/") + "/api/ingest"
    payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
    request = urllib_request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
            "User-Agent": f"siem-agent/{AGENT_VERSION}",
        },
    )

    try:
        with urllib_request.urlopen(request, timeout=timeout) as response:
            status = response.status
            raw = response.read()
    except HTTPError as exc:
        # HTTPError is a URLError too, so it must be caught first. The server
        # answered; the answer was a refusal (a bad key is a 401 here).
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="replace")[:200]
        except Exception:  # pragma: no cover - body already consumed/closed
            detail = ""
        raise ShipError(
            f"{url} returned HTTP {exc.code}"
            + (f": {detail}" if detail.strip() else "")
        ) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ShipError(f"could not reach {url}: {exc}") from exc

    if not 200 <= int(status) < 300:
        raise ShipError(f"{url} returned HTTP {status}")

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ShipError(f"{url} did not return JSON") from exc
    if not isinstance(parsed, dict):
        raise ShipError(f"{url} returned JSON that is not an object")
    return parsed


def _ship_batches(
    events: list[dict[str, Any]],
    *,
    server: str,
    host_id: str,
    key: str,
    timeout: float,
    batch_size: int,
    poster: PosterFn,
) -> dict[str, Any]:
    """Ship ``events`` in batches of ``batch_size``; stop at the first failure.

    Returns ``{"sent", "acked", "leftover", "error"}``. ``leftover`` is the
    failed batch and everything after it, oldest first, so the caller can spool
    it without reordering. ``error`` is ``""`` on full success.
    """

    sent = 0
    acked = 0
    for start in range(0, len(events), batch_size):
        chunk = events[start : start + batch_size]
        try:
            response = poster(server, host_id, key, chunk, timeout)
        except ShipError as exc:
            return {"sent": sent, "acked": acked, "leftover": events[sent:], "error": str(exc)}
        accepted = response.get("accepted", 0)
        try:
            acked += int(accepted or 0)
        except (TypeError, ValueError):
            acked += 0
        sent += len(chunk)
    return {"sent": sent, "acked": acked, "leftover": [], "error": ""}


# --------------------------------------------------------------------------- #
# Spool
# --------------------------------------------------------------------------- #

def _json_line(event: dict[str, Any]) -> str:
    return json.dumps(event, ensure_ascii=False, sort_keys=True)


def spool_append(path: Path | str, events: list[dict[str, Any]]) -> int:
    """Append ``events`` to the spool as JSONL, oldest first. Returns the count.

    Creates the parent directory and the file when they do not exist.
    """

    if not events:
        return 0
    spool = Path(path)
    parent = spool.parent
    if str(parent):
        parent.mkdir(parents=True, exist_ok=True)
    with open(spool, "a", encoding="utf-8") as handle:
        for event in events:
            handle.write(_json_line(event) + "\n")
    return len(events)


def spool_read(path: Path | str) -> list[dict[str, Any]]:
    """Read the spool oldest first.

    Blank lines and lines that are not a JSON object are skipped rather than
    raising: a process killed mid-write leaves a torn final line, and one torn
    line must not stop every later event from being delivered.
    """

    spool = Path(path)
    if not spool.exists():
        return []
    events: list[dict[str, Any]] = []
    with open(spool, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict):
                events.append(item)
    return events


def spool_size(path: Path | str) -> int:
    """Current spool size in bytes, or 0 when it does not exist."""

    spool = Path(path)
    return spool.stat().st_size if spool.exists() else 0


def spool_clear(path: Path | str) -> None:
    """Remove the spool file. Missing file is not an error."""

    Path(path).unlink(missing_ok=True)


def _spool_write(path: Path | str, events: list[dict[str, Any]]) -> int:
    """Replace the spool with exactly ``events``, atomically. Returns the count."""

    spool = Path(path)
    if not events:
        spool_clear(spool)
        return 0
    parent = spool.parent
    if str(parent):
        parent.mkdir(parents=True, exist_ok=True)
    temporary = spool.with_name(spool.name + ".tmp")
    with open(temporary, "w", encoding="utf-8") as handle:
        for event in events:
            handle.write(_json_line(event) + "\n")
    os.replace(temporary, spool)
    return len(events)


def spool_trim(path: Path | str, max_bytes: int) -> int:
    """Drop oldest spool entries until the file is at most ``max_bytes``.

    Returns the number of entries dropped, which the caller reports. A spool
    whose single oldest entry is itself larger than the bound is emptied, so the
    count can equal every entry. ``max_bytes`` of 0 or less disables trimming.
    """

    spool = Path(path)
    if max_bytes is None or max_bytes <= 0 or not spool.exists():
        return 0
    data = spool.read_bytes()
    if len(data) <= max_bytes:
        return 0

    # Each element of the split, plus its trailing newline, is one entry. The
    # final element is b"" when the file ended with a newline.
    lines = data.split(b"\n")
    total = len(data)
    index = 0
    while total > max_bytes and index < len(lines):
        total -= len(lines[index]) + 1
        index += 1
    dropped = index
    remaining = lines[index:]
    new_data = b"\n".join(remaining)
    if new_data and not new_data.endswith(b"\n"):
        new_data += b"\n"
    temporary = spool.with_name(spool.name + ".tmp")
    temporary.write_bytes(new_data)
    os.replace(temporary, spool)
    return dropped


# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonicalise(event: dict[str, Any], default_source: str) -> dict[str, Any]:
    """Fill the canonical keys a file-sourced event may be missing.

    Only missing keys get a neutral default; a value the source provided is
    passed through unchanged so the server, not the agent, decides what it
    means.
    """

    result = dict(event)
    result.setdefault("source", default_source)
    result.setdefault("timestamp", _now_iso())
    if not str(result.get("message") or "").strip():
        result["message"] = str(result.get("event") or "") or _json_line(event)
    result.setdefault("severity", "Low")
    result.setdefault("channel", "file")
    result.setdefault("provider", "file")
    result.setdefault("event_id", "")
    result.setdefault("level", "Information")
    result.setdefault("username", "unknown")
    result.setdefault("host", "unknown")
    result.setdefault("source_ip", "local")
    result.setdefault("is_alert", False)
    result.setdefault("rule_name", "")
    result.setdefault("record_id", "")
    return result


def _parse_file_line(
    path: Path,
    line: str,
    csv_fields: list[str] | None,
) -> tuple[list[dict[str, Any]], list[str] | None, int]:
    """Parse one complete line of a JSONL or CSV file.

    Returns ``(events, csv_fields, errors)``. For CSV the first non-empty line is
    the header and yields no events. A malformed line is counted as an error and
    skipped rather than raising, so one bad line cannot halt forwarding.
    """

    if path.suffix.lower() == ".csv":
        try:
            values = next(csv.reader([line]))
        except csv.Error:
            return [], csv_fields, 1
        if csv_fields is None:
            return [], [str(name).strip() for name in values], 0
        row = {
            csv_fields[i]: (values[i] if i < len(values) else "")
            for i in range(len(csv_fields))
        }
        return [_canonicalise(row, "agent-file")], csv_fields, 0

    try:
        item = json.loads(line)
    except ValueError:
        return [], csv_fields, 1
    if isinstance(item, dict):
        return [_canonicalise(item, "agent-file")], csv_fields, 0
    if isinstance(item, list):
        events = [_canonicalise(entry, "agent-file") for entry in item if isinstance(entry, dict)]
        return events, csv_fields, 0
    return [], csv_fields, 1


def _collect_file(path: Path, state: dict[str, Any]) -> list[dict[str, Any]]:
    """Tail a JSONL or CSV file, returning only records added since the last call.

    Progress is kept in ``state["file_offset"]`` and, for CSV,
    ``state["csv_fields"]``. Only newline-terminated lines are consumed; a
    partial final line waits in ``state["pending"]`` until its newline arrives,
    so appending to a half-written line is safe. Malformed lines are skipped and
    counted in ``state["file_errors"]``.
    """

    if not path.exists():
        return []

    try:
        size = path.stat().st_size
    except OSError:
        return []

    offset = int(state.get("file_offset", 0))
    if size < offset:
        # The file was truncated or rotated under us; start over.
        offset = 0
        state["pending"] = ""
        state["csv_fields"] = None

    with open(path, "rb") as handle:
        handle.seek(offset)
        chunk = handle.read()
    state["file_offset"] = size

    data = str(state.get("pending", "")) + chunk.decode("utf-8", errors="replace")
    if "\n" not in data:
        state["pending"] = data
        return []
    complete = data.split("\n")
    remainder = complete.pop()
    state["pending"] = remainder

    csv_fields = state.get("csv_fields")
    events: list[dict[str, Any]] = []
    errors = int(state.get("file_errors", 0))
    for line in complete:
        line = line.strip()
        if not line:
            continue
        parsed, csv_fields, line_errors = _parse_file_line(path, line, csv_fields)
        events.extend(parsed)
        errors += line_errors
    state["csv_fields"] = csv_fields
    state["file_errors"] = errors
    return events


def _collect_windows(
    state: dict[str, Any],
    channels: tuple[str, ...],
    backfill_per_channel: int,
) -> list[dict[str, Any]]:
    """Reuse :mod:`windows_collector` for one poll, capturing its payloads.

    The real collector normally writes to SQLite; here its ingest callback is
    redirected to a list so the same event-log reading, self-generated-record
    filtering and payload conversion are used without a database. On a non-
    Windows host PowerShell is absent, the collector records that per channel
    and returns nothing rather than raising.
    """

    captured: list[dict[str, Any]] = []

    def capture(
        db_path: Any,
        payloads: list[dict[str, Any]],
        source_default: str = "windows-event-log",
        *,
        notifier: Any = None,
    ) -> int:
        captured.extend(payloads)
        return len(payloads)

    collector: WindowsEventCollector | None = state.get("_windows_collector")
    if collector is None:
        collector = WindowsEventCollector(
            Path("."),
            capture,
            channels=tuple(channels),
            backfill_per_channel=backfill_per_channel,
        )
        collector.ingest = capture
        state["_windows_collector"] = collector

    if not state.get("windows_ready"):
        collector._initialise()
        state["windows_ready"] = True
    else:
        for channel in channels:
            try:
                records = collector._new_records(channel, collector.cursors.get(channel, 0))
                collector._ingest_records(channel, records, backfill=False)
                collector.cursors.setdefault(channel, 0)
            except (RuntimeError, ValueError, json.JSONDecodeError, OSError):
                # A channel that cannot be read is a fact about the machine.
                # The collector's own status already records it; keep going.
                continue
    return captured


def collect_events(
    source: str,
    *,
    file_path: Path | str | None = None,
    state: dict[str, Any] | None = None,
    collector: CollectorFn | None = None,
    channels: tuple[str, ...] = CHANNELS,
    backfill_per_channel: int = 25,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Collect raw canonical event dicts for one poll.

    ``source`` is ``"windows"`` or ``"file"``; anything else raises
    ``ValueError``. Pass ``collector`` (a zero-argument callable) to bypass both
    real sources in tests. ``state`` carries progress between calls; pass the
    same dict each time. ``limit`` caps the number returned, dropping the
    oldest excess, and is used to honour ``--batch-size``.
    """

    if source not in VALID_SOURCES:
        raise ValueError(f"source must be one of {VALID_SOURCES}, not {source!r}")
    if state is None:
        state = {}

    if collector is not None:
        events = list(collector())
    elif source == "windows":
        events = _collect_windows(state, tuple(channels), backfill_per_channel)
    else:
        if file_path is None:
            raise ValueError("the file source needs a file_path")
        events = _collect_file(Path(file_path), state)

    events = [event for event in events if isinstance(event, dict)]
    if limit is not None:
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        events = events[:limit]
    return events


# --------------------------------------------------------------------------- #
# One cycle and the loop
# --------------------------------------------------------------------------- #

def _run_cycle(
    *,
    server: str,
    host_id: str,
    key: str,
    source: str,
    spool_path: Path | str,
    batch_size: int,
    timeout: float,
    max_spool_bytes: int,
    collector: CollectorFn | None,
    poster: PosterFn,
    file_path: Path | str | None,
    channels: tuple[str, ...],
    backfill_per_channel: int,
    state: dict[str, Any],
) -> dict[str, Any]:
    """Collect once, drain the spool, ship, spool on failure, then bound the spool.

    Returns a per-cycle status dict. Never raises for a shipping failure; the
    failure is recorded in ``error`` and the events are kept in the spool.
    """

    collected = collect_events(
        source,
        file_path=file_path,
        state=state,
        collector=collector,
        channels=channels,
        backfill_per_channel=backfill_per_channel,
    )

    acked = 0
    shipped = 0
    spooled = 0
    error = ""

    # The spool is drained first, oldest first, so a recovered server receives
    # the backlog in the order it happened before anything new.
    pending = spool_read(spool_path)
    if pending:
        result = _ship_batches(
            pending,
            server=server,
            host_id=host_id,
            key=key,
            timeout=timeout,
            batch_size=batch_size,
            poster=poster,
        )
        shipped += result["sent"]
        acked += result["acked"]
        if result["leftover"]:
            error = result["error"]
            _spool_write(spool_path, result["leftover"])
        else:
            spool_clear(spool_path)

    # Then the events just collected.
    if collected:
        result = _ship_batches(
            collected,
            server=server,
            host_id=host_id,
            key=key,
            timeout=timeout,
            batch_size=batch_size,
            poster=poster,
        )
        shipped += result["sent"]
        acked += result["acked"]
        if result["leftover"]:
            error = result["error"] or error
            spooled += spool_append(spool_path, result["leftover"])

    dropped = spool_trim(spool_path, max_spool_bytes)
    return {
        "collected": len(collected),
        "shipped": shipped,
        "spooled": spooled,
        "dropped": dropped,
        "acked": acked,
        "spool_bytes": spool_size(spool_path),
        "error": error,
    }


def _status_line(cycle: int, result: dict[str, Any]) -> str:
    return (
        f"[agent] cycle={cycle} collected={result['collected']} "
        f"shipped={result['shipped']} spooled={result['spooled']} "
        f"dropped={result['dropped']} ack={result['acked']} "
        f"spool_bytes={result['spool_bytes']}"
    )


def run_agent(
    server: str,
    host_id: str,
    key: str,
    *,
    source: str = "windows",
    interval: float = DEFAULT_INTERVAL,
    spool_path: Path | str = DEFAULT_SPOOL_PATH,
    batch_size: int = DEFAULT_BATCH_SIZE,
    once: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    max_spool_bytes: int = DEFAULT_MAX_SPOOL_BYTES,
    collector: CollectorFn | None = None,
    poster: PosterFn | None = None,
    file_path: Path | str | None = None,
    channels: tuple[str, ...] = CHANNELS,
    backfill_per_channel: int = 25,
    state: dict[str, Any] | None = None,
    out: Callable[[str], None] = print,
    sleep: Callable[[float], None] = time.sleep,
    max_cycles: int | None = None,
) -> dict[str, Any]:
    """Collect and ship on an interval until stopped, or for one cycle.

    ``once=True`` performs exactly one collect-ship cycle and returns; that is
    what the ``--once`` flag and the tests use. ``max_cycles`` bounds a looping
    run for tests. ``collector`` and ``poster`` are the injection points that let
    the whole loop be exercised without a network or a real event source.

    Returns a run summary with ``cycles``, ``collected``, ``shipped``,
    ``spooled``, ``dropped``, ``acknowledged``, ``spool_bytes``, ``last_error``
    and ``ok`` (true when no cycle failed).
    """

    if source not in VALID_SOURCES:
        raise ValueError(f"source must be one of {VALID_SOURCES}, not {source!r}")
    if source == "file" and file_path is None:
        raise ValueError("the file source needs a file_path")
    if batch_size <= 0:
        raise ValueError("batch_size must be greater than zero")
    if interval < 0:
        raise ValueError("interval cannot be negative")
    if not server or not str(server).strip():
        raise ValueError("server URL is required")
    if not host_id or not str(host_id).strip():
        raise ValueError("host_id is required")

    resolved_poster = poster or ship_batch
    shared_state: dict[str, Any] = {} if state is None else state
    summary = {
        "server": str(server),
        "host_id": str(host_id),
        "source": source,
        "cycles": 0,
        "collected": 0,
        "shipped": 0,
        "spooled": 0,
        "dropped": 0,
        "acknowledged": 0,
        "spool_bytes": spool_size(spool_path),
        "last_error": "",
        "ok": True,
    }

    cycle = 0
    while True:
        cycle += 1
        result = _run_cycle(
            server=str(server),
            host_id=str(host_id),
            key=key,
            source=source,
            spool_path=spool_path,
            batch_size=batch_size,
            timeout=timeout,
            max_spool_bytes=max_spool_bytes,
            collector=collector,
            poster=resolved_poster,
            file_path=file_path,
            channels=channels,
            backfill_per_channel=backfill_per_channel,
            state=shared_state,
        )
        summary["cycles"] = cycle
        summary["collected"] += result["collected"]
        summary["shipped"] += result["shipped"]
        summary["spooled"] += result["spooled"]
        summary["dropped"] += result["dropped"]
        summary["acknowledged"] += result["acked"]
        summary["spool_bytes"] = result["spool_bytes"]
        if result["error"]:
            summary["last_error"] = result["error"]
            summary["ok"] = False

        out(_status_line(cycle, result))
        if result["error"]:
            out(f"[agent] error: {result['error']}")

        if once or (max_cycles is not None and cycle >= max_cycles):
            break
        sleep(interval)

    return summary


# --------------------------------------------------------------------------- #
# Command line
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    """The argument parser, exposed so tests can check the interface."""

    parser = argparse.ArgumentParser(
        prog="python -m src.agent",
        description="Forward local events to a central SIEM server.",
    )
    parser.add_argument("--server", required=True, help="Base URL of the SIEM server.")
    parser.add_argument("--host-id", required=True, help="Name this machine reports as.")
    parser.add_argument(
        "--key",
        default=os.environ.get("SIEM_AGENT_KEY", ""),
        help="Bearer key for /api/ingest. Defaults to $SIEM_AGENT_KEY.",
    )
    parser.add_argument(
        "--source",
        choices=VALID_SOURCES,
        default="windows",
        help="Where events come from. Default windows.",
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=None,
        help="JSONL or CSV file to tail when --source file.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help=f"Seconds between cycles. Default {DEFAULT_INTERVAL}.",
    )
    parser.add_argument(
        "--spool",
        type=Path,
        default=DEFAULT_SPOOL_PATH,
        help=f"Unsent-events spool path. Default {DEFAULT_SPOOL_PATH}.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Events per POST. Default {DEFAULT_BATCH_SIZE}.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Per-request timeout in seconds. Default {DEFAULT_TIMEOUT}.",
    )
    parser.add_argument(
        "--max-spool-bytes",
        type=int,
        default=DEFAULT_MAX_SPOOL_BYTES,
        help=(
            "Cap the spool; oldest entries are dropped past it. "
            f"Default {DEFAULT_MAX_SPOOL_BYTES}."
        ),
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one collect-ship cycle and exit. For scripting and tests.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m src.agent``. Returns a process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.source == "file" and args.file is None:
        parser.error("--source file requires --file")
    if not args.key:
        parser.error("--key is required (or set SIEM_AGENT_KEY)")

    summary = run_agent(
        args.server,
        args.host_id,
        args.key,
        source=args.source,
        interval=args.interval,
        spool_path=args.spool,
        batch_size=args.batch_size,
        once=args.once,
        timeout=args.timeout,
        max_spool_bytes=args.max_spool_bytes,
        file_path=args.file,
    )
    return 0 if summary["ok"] else 1


if __name__ == "__main__":  # pragma: no cover - exercised via subprocess
    raise SystemExit(main())
