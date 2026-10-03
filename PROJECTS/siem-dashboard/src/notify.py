"""Send alerts somewhere a person will actually see them.

A dashboard that only shows alerts on a page is a log viewer. This writes new
alerts to a file and, when configured, posts them to a webhook, so an alert can
reach a chat channel or a ticketing system without anyone watching the page.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3}

WEBHOOK_TIMEOUT = 5


class Notifier:
    """Deliver alerts above a severity threshold."""

    def __init__(
        self,
        *,
        webhook: str | None = None,
        log_path: Path | None = None,
        min_severity: str = "Medium",
    ) -> None:
        self.webhook = (webhook or "").strip() or None
        self.log_path = Path(log_path) if log_path else None
        self.min_severity = min_severity if min_severity in SEVERITY_ORDER else "Medium"
        self.sent = 0
        self.failed = 0
        self.last_error = ""

    @property
    def enabled(self) -> bool:
        return bool(self.webhook or self.log_path)

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "webhook": bool(self.webhook),
            "log_path": str(self.log_path) if self.log_path else "",
            "min_severity": self.min_severity,
            "sent": self.sent,
            "failed": self.failed,
            "last_error": self.last_error,
        }

    def _wanted(self, payload: dict[str, Any]) -> bool:
        severity = str(payload.get("severity") or "Low")
        return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER[self.min_severity]

    def _write_log(self, record: dict[str, Any]) -> None:
        if not self.log_path:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    def _post(self, record: dict[str, Any]) -> None:
        if not self.webhook:
            return
        body = json.dumps(record, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.webhook,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=WEBHOOK_TIMEOUT):
                pass
        except (urllib.error.URLError, OSError, ValueError) as exc:
            # A broken webhook must not stop collection. The failure is recorded
            # and reported on the dashboard instead.
            self.failed += 1
            self.last_error = f"webhook: {exc}"

    def deliver(self, payloads: Iterable[dict[str, Any]]) -> int:
        """Notify about each new alert. Returns how many were delivered."""

        if not self.enabled:
            return 0

        delivered = 0
        for payload in payloads:
            if not payload.get("is_alert") or not self._wanted(payload):
                continue
            record = {
                "raised_at": datetime.now(timezone.utc).isoformat(),
                "timestamp": payload.get("timestamp"),
                "severity": payload.get("severity"),
                "rule_id": payload.get("rule_id") or "",
                "rule_name": payload.get("rule_name") or "",
                "techniques": payload.get("techniques") or "",
                "host": payload.get("host"),
                "username": payload.get("username"),
                "source_ip": payload.get("source_ip"),
                "channel": payload.get("channel"),
                "event_id": payload.get("event_id"),
                "message": payload.get("message"),
                "source": payload.get("source"),
            }
            try:
                self._write_log(record)
                self._post(record)
            except OSError as exc:
                self.failed += 1
                self.last_error = f"alert log: {exc}"
                continue
            self.sent += 1
            delivered += 1

        return delivered
