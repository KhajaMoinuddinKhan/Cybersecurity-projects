"""Live Windows Event Log collection, including Sysmon.

The collector reads the channels it can reach, converts each record into a
payload, and hands it to the ingestion pipeline. Classification is not decided
here any more: the payload goes to the rule engine, so a detection can be
changed by editing a rule file rather than this module.

Sysmon is in the channel list because it is where the useful host telemetry
lives. The Security log says an account logged on; Sysmon says which process
ran, with what command line, started by which parent, and what it connected to.

One thing this module has to defend against is itself. Reading a channel means
running PowerShell, and a running PowerShell writes to the PowerShell channel.
Without a filter the collector's own command prompt becomes the loudest source
in the store: on a quiet workstation it produced roughly nine of every ten
events, all of them console lifecycle records from the collector talking to
itself. Every PowerShell process this module starts has its process id recorded,
and records from those processes are counted and skipped.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from xml.etree import ElementTree

from .rules import RuleEngine, RuleError, shared_engine

PayloadIngestor = Callable[..., int]

CHANNELS = (
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-PowerShell/Operational",
)

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# How many of our own child process ids to remember. Windows reuses process ids,
# so this is a trade-off: too short and a recycled id lets our own noise back in,
# too long and a recycled id could hide a real event from an unrelated process.
OWN_PID_MEMORY = 400

# Kept for callers that import it directly. The authoritative rules now live in
# src/rules/*.yml; this is a view of the same data for older callers.
SUSPICIOUS_POWERSHELL = (
    "-enc",
    "-encodedcommand",
    "downloadstring",
    "invoke-webrequest",
    "invoke-expression",
    "frombase64string",
    "iex ",
)


def _legacy_rule_map() -> dict[tuple[str, str], tuple[str, str]]:
    """A (channel, event_id) view of the loaded rules.

    Built from the rule files so there is one source of truth. Only rules whose
    condition is a single selection keyed on channel and event_id appear here.
    """

    mapping: dict[tuple[str, str], tuple[str, str]] = {}
    try:
        engine = shared_engine()
    except RuleError:
        return mapping

    for rule in engine.rules:
        channel = str(rule.logsource.get("channel") or "").strip()
        event_id = str(rule.logsource.get("event_id") or "").strip()
        selection = rule.detection.get("selection")
        if not channel or not event_id or not isinstance(selection, dict):
            continue
        if rule.condition.strip() != "selection":
            continue
        if set(selection) != {"event_id"}:
            continue
        mapping[(channel, event_id)] = (rule.level, rule.title)
    return mapping


class _LazyRules(dict):
    """A dict that builds itself from the rule files on first use."""

    def __init__(self) -> None:
        super().__init__()
        self._built = False

    def _ensure(self) -> None:
        if not self._built:
            self._built = True
            super().update(_legacy_rule_map())

    def __contains__(self, key: object) -> bool:
        self._ensure()
        return super().__contains__(key)

    def __getitem__(self, key: Any) -> Any:
        self._ensure()
        return super().__getitem__(key)

    def __len__(self) -> int:
        self._ensure()
        return super().__len__()

    def __iter__(self):
        self._ensure()
        return super().__iter__()

    def get(self, key: Any, default: Any = None) -> Any:
        self._ensure()
        return super().get(key, default)

    def items(self):
        self._ensure()
        return super().items()


RULES = _LazyRules()


# Windows reports a missing log and a log the account cannot read with different
# error ids. Both are normal on a real machine and neither is a fault in this
# application, so they are separated from genuine failures before they reach the
# dashboard. A raw PowerShell stack trace in an operator's console is noise.
CHANNEL_ERRORS = (
    ("NoMatchingLogsFound", "missing", "does not exist on this machine"),
    ("UnauthorizedAccess", "denied", "cannot be read by this account"),
    ("AccessDenied", "denied", "cannot be read by this account"),
    ("Attempted to perform an unauthorized operation", "denied", "cannot be read by this account"),
    ("The system cannot find the file specified", "missing", "does not exist on this machine"),
)


def describe_channel_error(channel: str, error: object) -> tuple[str, str]:
    """Turn a PowerShell failure into a state and a short sentence.

    Returns ``(state, message)`` where state is one of ``missing``, ``denied`` or
    ``error``. Only the last of those is a problem with this application.
    """

    text = str(error or "").strip()
    for needle, state, explanation in CHANNEL_ERRORS:
        if needle.lower() in text.lower():
            return state, f"{channel} {explanation}."
    first_line = text.splitlines()[0].strip() if text else "unknown failure"
    return "error", f"{channel}: {first_line[:200]}"


def severity_from_windows_level(level: str | None) -> str:
    """Map Windows operational levels to dashboard severity."""

    value = (level or "").strip().lower()
    if value in {"critical", "error"}:
        return "High"
    if value == "warning":
        return "Medium"
    return "Low"


def _event_data(xml_text: str | None) -> dict[str, str]:
    """Extract named EventData fields from Windows event XML."""

    if not xml_text:
        return {}

    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return {}

    fields: dict[str, str] = {}
    for element in root.iter():
        if not element.tag.endswith("Data"):
            continue
        name = element.attrib.get("Name")
        if name:
            fields[name] = element.text or ""
    return fields


def classify_event(
    channel: str,
    event_id: str,
    level: str,
    message: str,
    fields: dict[str, str] | None = None,
) -> tuple[str, bool, str]:
    """Apply the loaded rules to one event.

    Returns ``(severity, is_alert, rule_name)``. The optional ``fields`` mapping
    carries structured EventData, which is what lets a Sysmon rule match on a
    command line rather than on an event id alone.
    """

    payload = {
        "channel": channel,
        "event_id": event_id,
        "level": level,
        "message": message,
        "fields": fields or {},
    }
    try:
        match = shared_engine().match(payload)
    except RuleError:
        match = None

    if match is not None:
        return match.severity, True, match.title

    return severity_from_windows_level(level), False, ""


def windows_event_to_payload(log_name: str, item: dict[str, Any]) -> dict[str, Any]:
    """Convert one actual Windows event record into the SIEM format."""

    event_id = str(item.get("Id") or "unknown")
    provider = str(item.get("Provider") or "Windows")
    level = str(item.get("Level") or "Information")
    message = str(item.get("Message") or "").strip()
    if not message:
        message = f"{provider} event {event_id}"

    data = _event_data(str(item.get("Xml") or ""))
    username = (
        data.get("TargetUserName")
        or data.get("SubjectUserName")
        or data.get("AccountName")
        or data.get("User")
        or str(item.get("User") or "unknown")
    )
    source_ip = (
        data.get("IpAddress")
        or data.get("SourceNetworkAddress")
        or data.get("ClientAddress")
        or data.get("SourceIp")
        or "local"
    )
    if source_ip in {"-", "::1", "127.0.0.1"}:
        source_ip = "local"

    severity, is_alert, rule_name = classify_event(
        log_name,
        event_id,
        level,
        message,
        data,
    )

    record_id = str(item.get("RecordId") or "")
    raw = {key: value for key, value in item.items() if key != "Xml"}
    raw["EventData"] = data

    return {
        "timestamp": item.get("TimeCreated"),
        "channel": log_name,
        "provider": provider,
        "event_id": event_id,
        "level": level,
        "severity": severity,
        "username": username or "unknown",
        "host": str(item.get("Machine") or "localhost"),
        "source_ip": source_ip,
        "message": message,
        "record_id": record_id,
        "source": "windows-event-log",
        "is_alert": is_alert,
        "rule_name": rule_name,
        "external_id": f"{log_name}:{record_id}" if record_id else "",
        "raw_log": json.dumps(raw, ensure_ascii=False, sort_keys=True),
        "fields": data,
    }


class WindowsEventCollector:
    """Backfill recent Windows records, then continue collecting new ones."""

    def __init__(
        self,
        db_path: Path,
        ingest: PayloadIngestor,
        channels: tuple[str, ...] = CHANNELS,
        interval: float = 2.0,
        backfill_per_channel: int = 25,
        notifier: Any = None,
    ) -> None:
        self.db_path = db_path
        self.ingest = ingest
        self.channels = channels
        self.interval = interval
        self.backfill_per_channel = backfill_per_channel
        self.notifier = notifier
        # Process ids of the PowerShell children this collector has started, most
        # recent last. Bounded, so a long run cannot grow it without limit.
        self._own_pids: dict[int, None] = {}
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.cursors: dict[str, int] = {}
        self.status: dict[str, Any] = {
            "enabled": os.name == "nt",
            "running": False,
            "ingested": 0,
            "backfilled": 0,
            "alerts": 0,
            "self_skipped": 0,
            "channels": {name: {"state": "waiting", "last_record": 0} for name in channels},
            "last_error": "",
            "last_poll": "",
        }

    def start(self) -> None:
        if os.name != "nt":
            self.status["last_error"] = "Windows Event Log collection is available on Windows only."
            return
        if self.thread and self.thread.is_alive():
            return

        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._run,
            name="windows-event-collector",
            daemon=True,
        )
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3)

    def _remember_pid(self, pid: int) -> None:
        self._own_pids[pid] = None
        while len(self._own_pids) > OWN_PID_MEMORY:
            self._own_pids.pop(next(iter(self._own_pids)))

    def _is_own_pid(self, pid: int) -> bool:
        return pid in self._own_pids

    def _powershell(self, script: str) -> str:
        prefix = (
            "$OutputEncoding=[Console]::OutputEncoding="
            "[System.Text.UTF8Encoding]::new();"
            "$ProgressPreference='SilentlyContinue';"
        )
        process = subprocess.Popen(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                prefix + script,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        # Record the child before waiting: it is already writing to the event log.
        self._remember_pid(process.pid)

        try:
            stdout, stderr = process.communicate(timeout=18)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise RuntimeError("PowerShell command timed out")

        if process.returncode != 0:
            error = (stderr or "").strip() or (stdout or "").strip() or "PowerShell command failed"
            raise RuntimeError(error)
        return (stdout or "").strip()

    @staticmethod
    def _projection() -> str:
        return (
            "Select-Object RecordId,Id,"
            "@{N='TimeCreated';E={$_.TimeCreated.ToUniversalTime().ToString('o')}},"
            "@{N='Level';E={$_.LevelDisplayName}},"
            "@{N='Provider';E={$_.ProviderName}},"
            "@{N='Machine';E={$_.MachineName}},"
            "@{N='User';E={if($_.UserId){$_.UserId.Value}else{'unknown'}}},"
            "@{N='ProcessId';E={$_.ProcessId}},"
            "Message,@{N='Xml';E={$_.ToXml()}}"
        )

    def _decode_records(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        data = json.loads(text)
        if isinstance(data, dict):
            return [data]
        return data if isinstance(data, list) else []

    def _recent_records(self, channel: str) -> list[dict[str, Any]]:
        script = (
            "$ErrorActionPreference='Stop';try {"
            f"@(Get-WinEvent -LogName '{channel}' -MaxEvents {self.backfill_per_channel} "
            "-ErrorAction Stop | Sort-Object RecordId | "
            + self._projection()
            + ") | ConvertTo-Json -Depth 5 -Compress"
            + "} catch {if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){ '[]' }else{throw}}"
        )
        return self._decode_records(self._powershell(script))

    def _new_records(self, channel: str, after_record_id: int) -> list[dict[str, Any]]:
        script = (
            "$ErrorActionPreference='Stop';try {"
            f"@(Get-WinEvent -LogName '{channel}' "
            f"-FilterXPath '*[System[EventRecordID > {after_record_id}]]' "
            "-Oldest -MaxEvents 100 -ErrorAction Stop | Sort-Object RecordId | "
            + self._projection()
            + ") | ConvertTo-Json -Depth 5 -Compress"
            + "} catch {if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){ '[]' }else{throw}}"
        )
        return self._decode_records(self._powershell(script))

    def _ingest_records(
        self,
        channel: str,
        records: list[dict[str, Any]],
        *,
        backfill: bool,
    ) -> None:
        if not records:
            return

        # Advance the cursor over every record, including the ones skipped below.
        # Stopping short would leave the collector re-reading the same records on
        # every poll.
        record_ids = [
            int(item["RecordId"])
            for item in records
            if str(item.get("RecordId") or "").isdigit()
        ]
        if record_ids:
            latest = max(record_ids)
            self.cursors[channel] = latest
            self.status["channels"][channel]["last_record"] = latest

        payloads: list[dict[str, Any]] = []
        skipped = 0
        for item in records:
            process_id = str(item.get("ProcessId") or "").strip()
            if process_id.isdigit() and self._is_own_pid(int(process_id)):
                skipped += 1
                continue
            payloads.append(windows_event_to_payload(channel, item))

        self.status["self_skipped"] += skipped
        if not payloads:
            return

        inserted = self.ingest(
            self.db_path,
            payloads,
            "windows-event-log",
            notifier=self.notifier,
        )
        if backfill:
            self.status["backfilled"] += inserted
        else:
            self.status["ingested"] += inserted
        self.status["alerts"] += sum(1 for payload in payloads if payload.get("is_alert"))

    def _initialise(self) -> None:
        for channel in self.channels:
            try:
                records = self._recent_records(channel)
                self._ingest_records(channel, records, backfill=True)
                if channel not in self.cursors:
                    self.cursors[channel] = 0
                self.status["channels"][channel]["state"] = "connected"
            except (
                RuntimeError,
                ValueError,
                json.JSONDecodeError,
                subprocess.SubprocessError,
                OSError,
            ) as exc:
                state, message = describe_channel_error(channel, exc)
                self.status["channels"][channel]["state"] = state
                self.status["channels"][channel]["error"] = message
                if state == "error":
                    self.status["last_error"] = message

    def _run(self) -> None:
        self.status["running"] = True
        self._initialise()

        while not self.stop_event.is_set():
            for channel in self.channels:
                try:
                    records = (
                        self._new_records(channel, self.cursors[channel])
                        if channel in self.cursors else self._recent_records(channel)
                    )
                    self._ingest_records(channel, records, backfill=False)
                    self.cursors.setdefault(channel, 0)
                    self.status["channels"][channel]["state"] = "connected"
                    self.status["channels"][channel]["error"] = ""
                except (
                    RuntimeError,
                    ValueError,
                    json.JSONDecodeError,
                    subprocess.SubprocessError,
                    OSError,
                ) as exc:
                    state, message = describe_channel_error(channel, exc)
                    self.status["channels"][channel]["state"] = state
                    self.status["channels"][channel]["error"] = message
                    # The summary line is set once, after every channel has been
                    # polled. Setting it here as well made it flap: a reader
                    # asking mid-cycle would see whichever channel failed last.

            self.status["last_poll"] = datetime.now(timezone.utc).isoformat()
            # A missing or denied channel is a fact about the machine, not an
            # error, so it does not raise the summary line. Only a genuine
            # failure does.
            faults = [
                item["error"]
                for item in self.status["channels"].values()
                if item["state"] == "error"
            ]
            self.status["last_error"] = faults[0] if faults else ""
            self.stop_event.wait(self.interval)

        self.status["running"] = False
