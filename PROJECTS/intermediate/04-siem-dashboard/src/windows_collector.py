"""Collect new Windows Event Log entries while the SIEM is running."""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable


PayloadIngestor = Callable[[Path, Iterable[dict[str, Any]], str], int]
DEFAULT_LOGS = ("System", "Application", "Security")


def severity_from_windows_level(level: str | None) -> str:
    """Map Windows event levels to the dashboard severity model."""

    value = (level or "").strip().lower()
    if value in {"critical", "error"}:
        return "High"
    if value == "warning":
        return "Medium"
    return "Low"


def windows_event_to_payload(log_name: str, item: dict[str, Any]) -> dict[str, Any]:
    """Convert one PowerShell event record into the SIEM event format."""

    event_id = str(item.get("Id") or "unknown")
    provider = str(item.get("Provider") or "Windows")
    message = str(item.get("Message") or "").strip()
    if not message:
        message = f"{provider} event {event_id}"

    record_id = str(item.get("RecordId") or "")
    return {
        "timestamp": item.get("TimeCreated"),
        "source_ip": "local",
        "event": message,
        "severity": severity_from_windows_level(str(item.get("Level") or "")),
        "username": str(item.get("User") or "unknown"),
        "host": str(item.get("Machine") or "localhost"),
        "source": f"Windows:{log_name}",
        "event_type": f"windows_event_{event_id}",
        "external_id": f"{log_name}:{record_id}" if record_id else "",
        "raw_log": json.dumps(item, ensure_ascii=False, sort_keys=True),
    }


class WindowsEventCollector:
    """Poll Windows Event Logs and ingest only records created after startup."""

    def __init__(
        self,
        db_path: Path,
        ingest: PayloadIngestor,
        logs: tuple[str, ...] = DEFAULT_LOGS,
        interval: float = 3.0,
    ) -> None:
        self.db_path = db_path
        self.ingest = ingest
        self.logs = logs
        self.interval = interval
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.cursors: dict[str, int] = {}
        self.status: dict[str, Any] = {
            "enabled": os.name == "nt",
            "running": False,
            "ingested": 0,
            "logs": {name: "waiting" for name in logs},
            "last_error": "",
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
            self.thread.join(timeout=2)

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
            timeout=12,
            check=False,
        )
        if result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip() or "PowerShell command failed"
            raise RuntimeError(error)
        return result.stdout.strip()

    def _latest_record_id(self, log_name: str) -> int:
        script = (
            f"$e=Get-WinEvent -LogName '{log_name}' -MaxEvents 1 -ErrorAction Stop;"
            "if($null -eq $e){'0'}else{[string]$e.RecordId}"
        )
        text = self._powershell(script)
        return int(text or "0")

    def _new_records(self, log_name: str, after_record_id: int) -> list[dict[str, Any]]:
        script = (
            f"$items=@(Get-WinEvent -FilterHashtable @{{LogName='{log_name}';"
            "StartTime=(Get-Date).AddMinutes(-5)}} -ErrorAction Stop | "
            f"Where-Object {{$_.RecordId -gt {after_record_id}}} | "
            "Sort-Object RecordId | Select-Object "
            "RecordId,Id,"
            "@{N='TimeCreated';E={$_.TimeCreated.ToUniversalTime().ToString('o')}},"
            "@{N='Level';E={$_.LevelDisplayName}},"
            "@{N='Provider';E={$_.ProviderName}},"
            "@{N='Machine';E={$_.MachineName}},"
            "@{N='User';E={if($_.UserId){$_.UserId.Value}else{'unknown'}}},"
            "Message);"
            "$items | ConvertTo-Json -Depth 4 -Compress"
        )
        text = self._powershell(script)
        if not text:
            return []
        data = json.loads(text)
        if isinstance(data, dict):
            return [data]
        return data if isinstance(data, list) else []

    def _initialise(self) -> None:
        for log_name in self.logs:
            try:
                self.cursors[log_name] = self._latest_record_id(log_name)
                self.status["logs"][log_name] = "connected"
            except (RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                self.status["logs"][log_name] = "unavailable"
                self.status["last_error"] = f"{log_name}: {exc}"

    def _run(self) -> None:
        self.status["running"] = True
        self._initialise()

        while not self.stop_event.is_set():
            for log_name in self.logs:
                if log_name not in self.cursors:
                    continue
                try:
                    records = self._new_records(log_name, self.cursors[log_name])
                    if not records:
                        continue

                    payloads = [windows_event_to_payload(log_name, item) for item in records]
                    inserted = self.ingest(self.db_path, payloads, f"Windows:{log_name}")
                    self.status["ingested"] += inserted
                    self.status["logs"][log_name] = "connected"

                    record_ids = [
                        int(item["RecordId"])
                        for item in records
                        if str(item.get("RecordId") or "").isdigit()
                    ]
                    if record_ids:
                        self.cursors[log_name] = max(record_ids)
                except (
                    RuntimeError,
                    ValueError,
                    json.JSONDecodeError,
                    subprocess.SubprocessError,
                    OSError,
                ) as exc:
                    self.status["logs"][log_name] = "error"
                    self.status["last_error"] = f"{log_name}: {exc}"

            self.stop_event.wait(self.interval)

        self.status["running"] = False
