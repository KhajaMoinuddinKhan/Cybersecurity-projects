"""Enrich an event with threat intelligence before it is judged.

A detection says an event looks wrong. Threat intelligence says whether the
address, domain or hash involved is already known to be bad. Those are different
questions, and a SIEM that can only answer the first one sends an analyst to a
search engine for the second.

This reads the SQLite store written by the Threat Intelligence Aggregator in
this repository (table ``iocs`` with ``type``, ``value`` and ``source``), so the
two projects work together instead of sitting in separate folders.
"""
from __future__ import annotations

import ipaddress
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

INDICATOR_RULE_ID = "ti-known-indicator"
INDICATOR_RULE_NAME = "Known malicious indicator (threat intelligence)"

# Indicator types the aggregator writes, and the event fields each one is
# checked against.
TYPE_FIELDS = {
    "ip": ("source_ip", "message"),
    "domain": ("host", "message"),
    "hash": ("message",),
    "url": ("message",),
}

HASH_PATTERN = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
DOMAIN_PATTERN = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}\b")
URL_PATTERN = re.compile(r"\b(?:https?|ftp)://[^\s\"']+", re.IGNORECASE)


class IntelError(ValueError):
    """The threat-intelligence store cannot be read."""


class ThreatIntel:
    """Indicators loaded from an aggregator database, ready to be matched."""

    def __init__(self, indicators: dict[str, dict[str, str]]) -> None:
        self.indicators = indicators

    @property
    def size(self) -> int:
        return len(self.indicators)

    @classmethod
    def load(cls, db_path: Path | None) -> "ThreatIntel":
        """Read every indicator. An absent store is an empty one, not an error."""

        if db_path is None:
            return cls({})
        path = Path(db_path)
        if not path.is_file():
            return cls({})

        try:
            with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as connection:
                connection.row_factory = sqlite3.Row
                rows = connection.execute(
                    "SELECT type, value, source FROM iocs"
                ).fetchall()
        except sqlite3.Error as exc:
            raise IntelError(f"Could not read threat intelligence from {path}: {exc}") from exc

        indicators: dict[str, dict[str, str]] = {}
        for row in rows:
            kind = str(row["type"] or "").strip().lower()
            value = str(row["value"] or "").strip()
            if not kind or not value:
                continue
            indicators[f"{kind}:{value.lower()}"] = {
                "type": kind,
                "value": value,
                "source": str(row["source"] or "unknown"),
            }
        return cls(indicators)

    def _lookup(self, kind: str, value: str) -> dict[str, str] | None:
        return self.indicators.get(f"{kind}:{value.strip().lower()}")

    def _ip_match(self, value: str) -> dict[str, str] | None:
        direct = self._lookup("ip", value)
        if direct:
            return direct
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            return None
        for indicator in self.indicators.values():
            if indicator["type"] != "ip":
                continue
            try:
                if address in ipaddress.ip_network(indicator["value"], strict=False):
                    return indicator
            except ValueError:
                continue
        return None

    def check(self, fields: dict[str, str]) -> list[dict[str, str]]:
        """Return every indicator that appears in these event fields."""

        if not self.indicators:
            return []

        found: dict[str, dict[str, str]] = {}

        address = fields.get("source_ip", "")
        if address and address not in {"local", "unknown"}:
            match = self._ip_match(address)
            if match:
                found[f"ip:{match['value']}"] = {**match, "field": "source_ip"}

        haystacks = {
            name: fields.get(name, "")
            for name in ("message", "host", "rule_name")
        }

        for field_name, text in haystacks.items():
            if not text:
                continue

            for token in URL_PATTERN.findall(text):
                match = self._lookup("url", token) or self._lookup("url", token.rstrip("/"))
                if match:
                    found[f"url:{match['value']}"] = {**match, "field": field_name}

            for token in DOMAIN_PATTERN.findall(text):
                match = self._lookup("domain", token)
                if match:
                    found[f"domain:{match['value']}"] = {**match, "field": field_name}

            for token in HASH_PATTERN.findall(text):
                match = self._lookup("hash", token)
                if match:
                    found[f"hash:{match['value']}"] = {**match, "field": field_name}

        return list(found.values())


def apply_enrichment(payload: dict[str, Any], intel: ThreatIntel) -> dict[str, Any]:
    """Attach indicator matches to an event, and alert on them.

    An event that was already an alert keeps the rule that fired: a threat-intel
    hit is recorded alongside it rather than replacing the reason it was flagged.
    """

    if not intel.size:
        return payload

    from .rules import event_fields

    matches = intel.check(event_fields(payload))
    if not matches:
        return payload

    enriched = dict(payload)
    enriched["enrichment"] = matches

    if not enriched.get("is_alert"):
        names = ", ".join(f"{item['type']} {item['value']}" for item in matches[:3])
        enriched["is_alert"] = True
        enriched["severity"] = "High"
        enriched["rule_id"] = INDICATOR_RULE_ID
        enriched["rule_name"] = INDICATOR_RULE_NAME
        enriched["techniques"] = "attack.command_and_control"
        enriched["message"] = (
            f"{payload.get('message', '')} | matches threat intelligence: {names}"
        ).strip(" |")

    return enriched
