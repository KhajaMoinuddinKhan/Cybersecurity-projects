"""Decode security-related 802.11 information elements from a live BSS record."""
from __future__ import annotations

from dataclasses import dataclass


_RSN_OUI = bytes.fromhex("000fac")
_WPA_OUI = bytes.fromhex("0050f2")
_WPA_VENDOR_TYPE = 1
_WPS_VENDOR_TYPE = 4

_RSN_CIPHERS = {
    1: "WEP-40",
    2: "TKIP",
    4: "CCMP-128",
    5: "WEP-104",
    8: "GCMP-128",
    9: "GCMP-256",
    10: "CCMP-256",
    11: "BIP-GMAC-128",
    12: "BIP-GMAC-256",
    13: "BIP-CMAC-256",
}
_WPA_CIPHERS = {1: "WEP-40", 2: "TKIP", 4: "CCMP-128", 5: "WEP-104"}
_RSN_AKMS = {
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    8: "SAE",
    9: "FT-SAE",
    11: "Suite-B",
    12: "Suite-B-192",
    13: "FILS-SHA256",
    14: "FILS-SHA384",
    15: "FT-FILS-SHA256",
    16: "FT-FILS-SHA384",
    18: "OWE",
}
_WPA_AKMS = {1: "802.1X", 2: "PSK"}


@dataclass(frozen=True)
class SecurityProfile:
    """Security properties advertised by a beacon or probe response."""

    protocols: tuple[str, ...]
    security_label: str
    authentication_suites: tuple[str, ...]
    pairwise_ciphers: tuple[str, ...]
    group_ciphers: tuple[str, ...]
    pmf_capable: bool | None
    pmf_required: bool | None
    wps_advertised: bool
    privacy_enabled: bool
    parse_errors: tuple[str, ...]


def _selector_name(selector: bytes, names: dict[int, str]) -> str:
    if len(selector) == 4:
        oui, number = selector[:3], selector[3]
        if oui in (_RSN_OUI, _WPA_OUI) and number in names:
            return names[number]
    return ":".join(f"{part:02x}" for part in selector)


def _parse_security_body(body: bytes, protocol: str) -> tuple[str, str, tuple[str, ...], tuple[str, ...], tuple[str, ...], int | None]:
    """Parse the version, group cipher, pairwise ciphers, AKMs and capabilities."""
    cursor = 0

    def take(size: int, field: str) -> bytes:
        nonlocal cursor
        if size < 0 or cursor + size > len(body):
            raise ValueError(f"truncated {field}")
        part = body[cursor:cursor + size]
        cursor += size
        return part

    def read_count(field: str) -> int:
        return int.from_bytes(take(2, field), "little")

    version = int.from_bytes(take(2, "version"), "little")
    if version != 1:
        raise ValueError(f"unsupported {protocol} version {version}")

    group_raw = take(4, "group cipher")
    pairwise_count = read_count("pairwise cipher count")
    if pairwise_count > (len(body) - cursor) // 4:
        raise ValueError("pairwise cipher count exceeds the information element")
    pairwise_raw = tuple(take(4, "pairwise cipher") for _ in range(pairwise_count))

    akm_count = read_count("authentication suite count")
    if akm_count > (len(body) - cursor) // 4:
        raise ValueError("authentication suite count exceeds the information element")
    akm_raw = tuple(take(4, "authentication suite") for _ in range(akm_count))

    capabilities: int | None = None
    if cursor < len(body):
        if len(body) - cursor < 2:
            raise ValueError("truncated capabilities field")
        capabilities = int.from_bytes(take(2, "capabilities"), "little")

    if cursor < len(body):
        if len(body) - cursor < 2:
            raise ValueError("truncated PMKID count")
        pmkid_count = read_count("PMKID count")
        if pmkid_count > (len(body) - cursor) // 16:
            raise ValueError("PMKID count exceeds the information element")
        take(pmkid_count * 16, "PMKID list")
        if cursor < len(body):
            if len(body) - cursor < 4:
                raise ValueError("truncated group management cipher")
            take(4, "group management cipher")

    cipher_names = _WPA_CIPHERS if protocol == "WPA" else _RSN_CIPHERS
    akm_names = _WPA_AKMS if protocol == "WPA" else _RSN_AKMS
    group_name = _selector_name(group_raw, cipher_names)
    pairwise_names = tuple(dict.fromkeys(_selector_name(item, cipher_names) for item in pairwise_raw))
    authentication_names = tuple(dict.fromkeys(_selector_name(item, akm_names) for item in akm_raw))
    return protocol, group_name, pairwise_names, authentication_names, akm_raw, capabilities


def _security_label(protocols: tuple[str, ...], authentication: tuple[str, ...], privacy: bool) -> str:
    if "RSN" in protocols:
        auth = set(authentication)
        if "OWE" in auth:
            return "Enhanced Open (OWE)"
        if "SAE" in auth and "PSK" in auth:
            return "WPA2/WPA3 transition"
        if "SAE" in auth:
            return "WPA3-Personal"
        if "PSK" in auth or "PSK-SHA256" in auth or "FT-PSK" in auth:
            return "WPA2-Personal"
        if any(name.startswith(("802.1X", "FT-802.1X", "Suite-B", "FILS", "FT-FILS")) for name in auth):
            return "WPA2-Enterprise"
        return "RSN-secured (authentication unresolved)"
    if "WPA" in protocols:
        return "WPA (legacy)"
    if privacy:
        return "WEP or unknown legacy privacy"
    return "Open"


def parse_security_information_elements(ies: bytes | bytearray | memoryview, *, privacy_enabled: bool) -> SecurityProfile:
    """Parse security and WPS advertisements without trusting AP-supplied lengths.

    ``ies`` must be the bounded IE blob returned with the BSS observation. This
    function never treats malformed or unknown security data as an open network.
    """
    if not isinstance(ies, (bytes, bytearray, memoryview)):
        raise TypeError("information elements must be bytes-like")
    data = bytes(ies)
    protocols: list[str] = []
    authentication: list[str] = []
    pairwise: list[str] = []
    group_ciphers: list[str] = []
    pmf_capable: bool | None = None
    pmf_required: bool | None = None
    wps_advertised = False
    parse_errors: list[str] = []
    malformed_security = False
    cursor = 0

    while cursor < len(data):
        remaining = len(data) - cursor
        if remaining < 2:
            parse_errors.append("truncated information element header")
            if data[cursor] in (48, 221):
                malformed_security = True
            break
        element_id = data[cursor]
        element_length = data[cursor + 1]
        cursor += 2
        if element_length > len(data) - cursor:
            parse_errors.append(f"information element {element_id} length exceeds remaining data")
            if element_id == 48 or (element_id == 221 and data[cursor:cursor + 4] == _WPA_OUI + bytes((_WPA_VENDOR_TYPE,))):
                malformed_security = True
            break
        payload = data[cursor:cursor + element_length]
        cursor += element_length

        protocol: str | None = None
        body = b""
        if element_id == 48:
            protocol = "RSN"
            body = payload
        elif element_id == 221 and payload[:4] == _WPA_OUI + bytes((_WPA_VENDOR_TYPE,)):
            protocol = "WPA"
            body = payload[4:]
        elif element_id == 221 and payload[:4] == _WPA_OUI + bytes((_WPS_VENDOR_TYPE,)):
            wps_advertised = True

        if protocol is None:
            continue
        if protocol in protocols:
            parse_errors.append(f"duplicate {protocol} security information element")
            malformed_security = True
            continue
        try:
            protocol_name, group, pairwise_names, auth_names, _, capabilities = _parse_security_body(body, protocol)
        except ValueError as exc:
            parse_errors.append(f"malformed {protocol} information element: {exc}")
            malformed_security = True
            continue

        protocols.append(protocol_name)
        group_ciphers.append(group)
        pairwise.extend(pairwise_names)
        authentication.extend(auth_names)
        if protocol == "RSN" and capabilities is not None:
            pmf_capable = bool(capabilities & (1 << 7))
            pmf_required = bool(capabilities & (1 << 6))

    protocol_tuple = tuple(protocol for protocol in ("WPA", "RSN") if protocol in protocols)
    auth_tuple = tuple(dict.fromkeys(authentication))
    if malformed_security:
        label = "Unknown (malformed security information)"
    else:
        label = _security_label(protocol_tuple, auth_tuple, bool(privacy_enabled))
    return SecurityProfile(
        protocols=protocol_tuple,
        security_label=label,
        authentication_suites=auth_tuple,
        pairwise_ciphers=tuple(dict.fromkeys(pairwise)),
        group_ciphers=tuple(dict.fromkeys(group_ciphers)),
        pmf_capable=pmf_capable,
        pmf_required=pmf_required,
        wps_advertised=wps_advertised,
        privacy_enabled=bool(privacy_enabled),
        parse_errors=tuple(parse_errors),
    )
