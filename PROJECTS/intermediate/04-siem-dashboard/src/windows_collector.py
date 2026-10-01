"""Live Windows Event Log collection and event-based security rules."""
from __future__ import annotations

import json
import os
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from xml.etree import ElementTree

PayloadIngestor = Callable[[Path, Iterable[dict[str, Any]], str], int]

CHANNELS = (
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-PowerShell/Operational",
)

RULES: dict[tuple[str, str], tuple[str, str]] = {
    ("Security", "1102"): ("High", "Windows audit log cleared"),
    ("Security", "4625"): ("Medium", "Failed Windows logon"),
    ("Security", "4720"): ("Medium", "User account created"),
    ("Security", "4726"): ("Medium", "User account deleted"),
    ("Security", "4728"): ("High", "Member added to a privileged group"),
    ("Security", "4732"): ("High", "Member added to a local privileged group"),
    ("Security", "4756"): ("High", "Member added to a universal group"),
    ("Security", "4740"): ("High", "User account locked out"),
    ("System", "7045"): ("High", "Windows service installed"),
    ("Microsoft-Windows-Windows Defender/Operational", "1116"): (
        "High",
        "Windows Defender detected malware",
    ),
    ("Microsoft-Windows-Windows Defender/Operational", "1117"): (
        "Medium",
        "Windows Defender remediation action",
    ),
}

SUSPICIOUS_POWERSHELL = (
    "-enc",
    "-encodedcommand",
    "downloadstring",
    "invoke-webrequest",
    "invoke-expression",
    "frombase64string",
    "iex ",
)


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
) -> tuple[str, bool, str]:
    """Apply small explainable rules to real Windows events."""

    key = (channel, event_id)
    if key in RULES:
        severity, rule_name = RULES[key]
        return severity, True, rule_name

    if (
        channel == "Microsoft-Windows-PowerShell/Operational"
        and event_id == "4104"
    ):
        lowered = message.lower()
        if any(term in lowered for term in SUSPICIOUS_POWERSHELL):
            return "High", True, "Suspicious PowerShell script block"

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
        or str(item.get("User") or "unknown")
    )
    source_ip = (
        data.get("IpAddress")
        or data.get("SourceNetworkAddress")
        or data.get("ClientAddress")
        or "local"
    )
    if source_ip in {"-", "::1", "127.0.0.1"}:
        source_ip = "local"

    severity, is_alert, rule_name = classify_event(
        log_name,
        event_id,
        level,
        message,
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
    ) -> None:
        self.db_path = db_path
        self.ingest = ingest
        self.channels = channels
        self.interval = interval
        self.backfill_per_channel = backfill_per_channel
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.cursors: dict[str, int] = {}
        self.status: dict[str, Any] = {
            "enabled": os.name == "nt",
            "running": False,
            "ingested": 0,
            "backfilled": 0,
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

    def _powershell(self, script: str) -> str:
        prefix = (
            "$OutputEncoding=[Console]::OutputEncoding="
            "[System.Text.UTF8Encoding]::new();"
            "$ProgressPreference='SilentlyContinue';"
        )
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                prefix + script,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=18,
            check=False,
        )
        if result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip() or "PowerShell command failed"
            raise RuntimeError(error)
        return result.stdout.strip()

    @staticmethod
    def _projection() -> str:
        return (
            "Select-Object RecordId,Id,"
            "@{N='TimeCreated';E={$_.TimeCreated.ToUniversalTime().ToString('o')}},"
            "@{N='Level';E={$_.LevelDisplayName}},"
            "@{N='Provider';E={$_.ProviderName}},"
            "@{N='Machine';E={$_.MachineName}},"
            "@{N='User';E={if($_.UserId){$_.UserId.Value}else{'unknown'}}},"
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

        payloads = [windows_event_to_payload(channel, item) for item in records]
        inserted = self.ingest(self.db_path, payloads, "windows-event-log")
        if backfill:
            self.status["backfilled"] += inserted
        else:
            self.status["ingested"] += inserted

        record_ids = [
            int(item["RecordId"])
            for item in records
            if str(item.get("RecordId") or "").isdigit()
        ]
        if record_ids:
            latest = max(record_ids)
            self.cursors[channel] = latest
            self.status["channels"][channel]["last_record"] = latest

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
                self.status["channels"][channel]["state"] = "unavailable"
                self.status["last_error"] = f"{channel}: {exc}"

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
                    self.status["channels"][channel]["state"] = "error"
                    self.status["channels"][channel]["error"] = str(exc)
                    self.status["last_error"] = f"{channel}: {exc}"

            self.status["last_poll"] = datetime.now(timezone.utc).isoformat()
            if all(item["state"] == "connected" for item in self.status["channels"].values()):
                self.status["last_error"] = ""
            self.stop_event.wait(self.interval)

        self.status["running"] = False
