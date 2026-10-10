"""Typed observations and findings emitted by the Wi-Fi analyzer."""
from __future__ import annotations

from dataclasses import dataclass
import re

from .ie_parser import SecurityProfile

_BSSID_PATTERN = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")


def normalize_bssid(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("BSSID must be text")
    normalized = value.strip().replace("-", ":").lower()
    if not _BSSID_PATTERN.fullmatch(normalized):
        raise ValueError("BSSID must contain six hexadecimal octets")
    octets = bytes(int(part, 16) for part in normalized.split(":"))
    if not any(octets) or octets[0] & 1:
        raise ValueError("BSSID must be a nonzero unicast address")
    return normalized


@dataclass(frozen=True)
class AccessPoint:
    ssid_bytes: bytes
    bssid: str
    rssi_dbm: int
    signal_quality: int
    center_frequency_khz: int
    phy_type: int
    capability_information: int
    security: SecurityProfile
    phy_id: int | None = None
    bss_type: int | None = None
    beacon_period_tu: int | None = None
    ap_timestamp_us: int | None = None
    host_timestamp_us: int | None = None
    in_regulatory_domain: bool | None = None
    supported_rates_raw: tuple[int, ...] = ()
    information_elements: bytes = b""

    def __post_init__(self) -> None:
        if not isinstance(self.ssid_bytes, (bytes, bytearray, memoryview)):
            raise TypeError("SSID must be bytes-like")
        ssid = bytes(self.ssid_bytes)
        if len(ssid) > 32:
            raise ValueError("SSID exceeds the 802.11 length limit")
        object.__setattr__(self, "ssid_bytes", ssid)
        object.__setattr__(self, "bssid", normalize_bssid(self.bssid))
        for name, value in (("RSSI", self.rssi_dbm), ("signal quality", self.signal_quality),
                            ("frequency", self.center_frequency_khz), ("PHY type", self.phy_type),
                            ("capability information", self.capability_information)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
        if not -128 <= self.rssi_dbm <= 0:
            raise ValueError("RSSI must be between -128 and 0 dBm")
        if not 0 <= self.signal_quality <= 100:
            raise ValueError("signal quality must be between 0 and 100")
        if self.center_frequency_khz < 0:
            raise ValueError("frequency cannot be negative")
        if not 0 <= self.phy_type <= 0xFFFFFFFF:
            raise ValueError("PHY type is outside the Windows WLAN range")
        if not 0 <= self.capability_information <= 0xFFFF:
            raise ValueError("capability information must fit in 16 bits")
        if not isinstance(self.security, SecurityProfile):
            raise TypeError("security must be a parsed SecurityProfile")
        for name, value, maximum in (
            ("PHY identifier", self.phy_id, 0xFFFFFFFF),
            ("BSS type", self.bss_type, 0xFFFFFFFF),
            ("beacon period", self.beacon_period_tu, 0xFFFF),
            ("AP timestamp", self.ap_timestamp_us, 0xFFFFFFFFFFFFFFFF),
            ("host timestamp", self.host_timestamp_us, 0xFFFFFFFFFFFFFFFF),
        ):
            if value is not None:
                if isinstance(value, bool) or not isinstance(value, int):
                    raise TypeError(f"{name} must be an integer")
                if not 0 <= value <= maximum:
                    raise ValueError(f"{name} is outside its native unsigned range")
        if self.in_regulatory_domain is not None and type(self.in_regulatory_domain) is not bool:
            raise TypeError("regulatory-domain flag must be a boolean")
        if not isinstance(self.supported_rates_raw, (tuple, list)):
            raise TypeError("rate set must be a tuple or list of integers")
        if len(self.supported_rates_raw) > 126:
            raise ValueError("rate set exceeds its native capacity")
        rates = tuple(self.supported_rates_raw)
        if any(isinstance(rate, bool) or not isinstance(rate, int) for rate in rates):
            raise TypeError("every rate-set value must be an integer")
        if any(not 0 <= rate <= 0xFFFF for rate in rates):
            raise ValueError("rate-set value must fit in 16 bits")
        object.__setattr__(self, "supported_rates_raw", rates)
        if not isinstance(self.information_elements, (bytes, bytearray, memoryview)):
            raise TypeError("information elements must be bytes-like")
        information_elements = bytes(self.information_elements)
        if len(information_elements) > 16 * 1024:
            raise ValueError("information elements exceed the safety limit")
        object.__setattr__(self, "information_elements", information_elements)

    @property
    def ssid_hex(self) -> str:
        return self.ssid_bytes.hex()

    @property
    def ssid_text(self) -> str:
        return self.ssid_bytes.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.severity not in {"HIGH", "MEDIUM", "LOW", "INFO"}:
            raise ValueError("severity must be HIGH, MEDIUM, LOW, or INFO")
        if not self.code or not self.message:
            raise ValueError("finding code and message are required")
        if not isinstance(self.evidence, tuple) or any(not isinstance(item, str) for item in self.evidence):
            raise TypeError("finding evidence must be a tuple of strings")


@dataclass(frozen=True)
class NetworkAssessment:
    access_point: AccessPoint
    findings: tuple[Finding, ...]
