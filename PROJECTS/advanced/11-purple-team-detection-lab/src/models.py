"""Data models shared by the detection pipeline."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    timestamp: datetime
    event_type: str
    source: str
    user: str
    host: str
    data: dict[str, Any]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SecurityEvent":
        required = ("event_id", "timestamp", "event_type", "source", "user", "host")
        missing = [key for key in required if not isinstance(raw.get(key), str) or not raw[key].strip()]
        if missing:
            raise ValueError("Event is missing: " + ", ".join(missing))

        try:
            timestamp = datetime.fromisoformat(str(raw["timestamp"]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid timestamp for event {raw.get('event_id', '?')}") from exc

        timestamp = timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp.astimezone(timezone.utc)

        data = raw.get("data", {})
        if not isinstance(data, dict):
            raise ValueError(f"Event {raw['event_id']} data must be an object")

        return cls(
            event_id=str(raw["event_id"]),
            timestamp=timestamp,
            event_type=str(raw["event_type"]),
            source=str(raw["source"]),
            user=str(raw["user"]),
            host=str(raw["host"]),
            data=data,
        )

    def field(self, name: str) -> Any:
        if name in {"event_id", "timestamp", "event_type", "source", "user", "host", "data"}:
            return getattr(self, name)
        return self.data.get(name)


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    title: str
    description: str
    severity: str
    technique_id: str
    technique_name: str
    rule_type: str
    conditions: tuple[dict[str, Any], ...]
    group_by: str | None = None
    threshold: int | None = None
    window_minutes: int | None = None


@dataclass(frozen=True)
class Alert:
    rule_id: str
    title: str
    description: str
    severity: str
    technique_id: str
    technique_name: str
    first_seen: datetime
    last_seen: datetime
    group_value: str
    event_ids: tuple[str, ...]
    host: str
    user: str
    source: str
