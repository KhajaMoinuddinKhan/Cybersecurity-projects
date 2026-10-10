"""Explicit allowlists sourced from observations made by a live scan."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from .ie_parser import SecurityProfile
from .models import AccessPoint, normalize_bssid

SCHEMA_VERSION = 1
MAX_BASELINE_BYTES = 1_048_576


@dataclass(frozen=True)
class BaselineEntry:
    bssid: str
    ssid_hex: str
    security: SecurityProfile


@dataclass(frozen=True)
class WifiBaseline:
    created_at: str
    access_points: tuple[BaselineEntry, ...]


def _profile_to_dict(profile: SecurityProfile) -> dict[str, Any]:
    return {
        "protocols": list(profile.protocols),
        "security_label": profile.security_label,
        "authentication_suites": list(profile.authentication_suites),
        "pairwise_ciphers": list(profile.pairwise_ciphers),
        "group_ciphers": list(profile.group_ciphers),
        "pmf_capable": profile.pmf_capable,
        "pmf_required": profile.pmf_required,
        "wps_advertised": profile.wps_advertised,
        "privacy_enabled": profile.privacy_enabled,
        "parse_errors": list(profile.parse_errors),
    }


def baseline_to_dict(baseline: WifiBaseline) -> dict[str, Any]:
    if not isinstance(baseline, WifiBaseline):
        raise TypeError("baseline must be a WifiBaseline")
    return {
        "schema_version": SCHEMA_VERSION,
        "created_at": baseline.created_at,
        "access_points": [
            {"bssid": entry.bssid, "ssid_hex": entry.ssid_hex, "security": _profile_to_dict(entry.security)}
            for entry in baseline.access_points
        ],
    }


def _strings(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 64 or any(not isinstance(x, str) or not x or len(x) > 160 for x in value):
        raise ValueError(f"invalid baseline field: {field}")
    return tuple(dict.fromkeys(value))


def _profile_from_dict(value: Any) -> SecurityProfile:
    names = {
        "protocols", "security_label", "authentication_suites", "pairwise_ciphers", "group_ciphers",
        "pmf_capable", "pmf_required", "wps_advertised", "privacy_enabled", "parse_errors",
    }
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError("invalid baseline security profile fields")
    for field in ("wps_advertised", "privacy_enabled"):
        if type(value[field]) is not bool:
            raise ValueError(f"invalid baseline field: {field}")
    for field in ("pmf_capable", "pmf_required"):
        if value[field] is not None and type(value[field]) is not bool:
            raise ValueError(f"invalid baseline field: {field}")
    label = value["security_label"]
    if not isinstance(label, str) or not label or len(label) > 160:
        raise ValueError("invalid baseline field: security_label")
    return SecurityProfile(
        protocols=_strings(value["protocols"], "protocols"),
        security_label=label,
        authentication_suites=_strings(value["authentication_suites"], "authentication_suites"),
        pairwise_ciphers=_strings(value["pairwise_ciphers"], "pairwise_ciphers"),
        group_ciphers=_strings(value["group_ciphers"], "group_ciphers"),
        pmf_capable=value["pmf_capable"],
        pmf_required=value["pmf_required"],
        wps_advertised=value["wps_advertised"],
        privacy_enabled=value["privacy_enabled"],
        parse_errors=_strings(value["parse_errors"], "parse_errors"),
    )


def baseline_from_dict(value: Any) -> WifiBaseline:
    if not isinstance(value, dict) or set(value) != {"schema_version", "created_at", "access_points"}:
        raise ValueError("baseline root must contain schema_version, created_at, and access_points")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported baseline schema version")
    created = value["created_at"]
    if not isinstance(created, str) or len(created) > 40:
        raise ValueError("invalid baseline field: created_at")
    try:
        parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid baseline field: created_at") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("baseline created_at must be UTC")

    records = value["access_points"]
    if not isinstance(records, list) or not records or len(records) > 4096:
        raise ValueError("baseline must contain 1 to 4096 access points")
    entries: list[BaselineEntry] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("baseline access-point record must be an object")
        missing = {"bssid", "ssid_hex", "security"} - set(record)
        extra = set(record) - {"bssid", "ssid_hex", "security"}
        if missing:
            raise ValueError("baseline access-point record missing fields: " + ", ".join(sorted(missing)))
        if extra:
            raise ValueError("baseline access-point record has unexpected fields: " + ", ".join(sorted(extra)))
        bssid = normalize_bssid(record["bssid"])
        if bssid in seen:
            raise ValueError(f"duplicate BSSID in baseline: {bssid}")
        seen.add(bssid)
        ssid_hex = record["ssid_hex"]
        if not isinstance(ssid_hex, str) or len(ssid_hex) > 64 or len(ssid_hex) % 2:
            raise ValueError("invalid baseline field: ssid_hex")
        if any(character not in "0123456789abcdefABCDEF" for character in ssid_hex):
            raise ValueError("invalid baseline field: ssid_hex")
        try:
            bytes.fromhex(ssid_hex)
        except ValueError as exc:
            raise ValueError("invalid baseline field: ssid_hex") from exc
        entries.append(BaselineEntry(bssid, ssid_hex.lower(), _profile_from_dict(record["security"])))
    return WifiBaseline(created, tuple(entries))


def build_baseline(observations, include_bssids, *, created_at: str | None = None) -> WifiBaseline:
    """Create an allowlist from explicitly selected BSSIDs in a live scan."""
    if not isinstance(observations, (list, tuple)) or any(not isinstance(ap, AccessPoint) for ap in observations):
        raise TypeError("observations must be a list or tuple of AccessPoint records")
    if not isinstance(include_bssids, (list, tuple)):
        raise TypeError("include_bssids must be a list or tuple")
    selected = tuple(dict.fromkeys(normalize_bssid(item) for item in include_bssids))
    if not selected:
        raise ValueError("include at least one BSSID observed in the live scan")
    observed: dict[str, AccessPoint] = {}
    for ap in observations:
        prior = observed.get(ap.bssid)
        if prior is not None and (prior.ssid_bytes, prior.security) != (ap.ssid_bytes, ap.security):
            raise ValueError(f"conflicting observations for BSSID {ap.bssid}")
        observed.setdefault(ap.bssid, ap)
    missing = [bssid for bssid in selected if bssid not in observed]
    if missing:
        raise ValueError("included BSSID not present in the scan: " + ", ".join(missing))
    entries = tuple(BaselineEntry(bssid, observed[bssid].ssid_hex, observed[bssid].security) for bssid in selected)
    timestamp = created_at if created_at is not None else datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    return baseline_from_dict({"schema_version": SCHEMA_VERSION, "created_at": timestamp,
                               "access_points": [{"bssid": e.bssid, "ssid_hex": e.ssid_hex,
                                                  "security": _profile_to_dict(e.security)} for e in entries]})


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_baseline(path: str | os.PathLike[str]) -> WifiBaseline:
    try:
        with Path(path).open("rb") as source:
            raw = source.read(MAX_BASELINE_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"cannot read baseline file: {exc}") from exc
    if len(raw) > MAX_BASELINE_BYTES:
        raise ValueError("baseline file exceeds the size limit")
    try:
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"invalid baseline JSON: {exc}") from exc
    return baseline_from_dict(data)


def write_baseline(path: str | os.PathLike[str], baseline: WifiBaseline, *, overwrite: bool = False) -> None:
    target = Path(path)
    if type(overwrite) is not bool:
        raise TypeError("overwrite must be a boolean")
    if not target.parent.exists() or not target.parent.is_dir():
        raise ValueError("baseline output directory does not exist")
    payload = (json.dumps(baseline_to_dict(baseline), ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=".wifi-baseline-", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        temporary = Path(temp_name)
        if overwrite:
            os.replace(temporary, target)
        else:
            os.link(temporary, target)
            temporary.unlink()
    except FileExistsError:
        raise
    except OSError as exc:
        raise ValueError(f"cannot write baseline file: {exc}") from exc
    finally:
        Path(temp_name).unlink(missing_ok=True)
