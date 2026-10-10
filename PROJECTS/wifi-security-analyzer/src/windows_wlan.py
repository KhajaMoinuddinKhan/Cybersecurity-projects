"""Windows Native Wi-Fi discovery with checked WLAN API buffers."""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import os
import threading
import time
import uuid
from typing import Any

from .channels import channel_details
from .ie_parser import parse_security_information_elements
from .models import AccessPoint

DWORD = ctypes.c_uint32
ULONG = ctypes.c_uint32
LONG = ctypes.c_int32
USHORT = ctypes.c_uint16
UCHAR = ctypes.c_uint8
BOOLEAN = ctypes.c_uint8
ULONGLONG = ctypes.c_uint64
HANDLE = ctypes.c_void_p
WCHAR16 = ctypes.c_uint16

WLAN_API_VERSION_2 = 2
WLAN_NOTIFICATION_SOURCE_NONE = 0
WLAN_NOTIFICATION_SOURCE_ACM = 0x00000008
WLAN_NOTIFICATION_ACM_SCAN_COMPLETE = 7
WLAN_NOTIFICATION_ACM_SCAN_FAIL = 8
WLAN_INTERFACE_STATE_CONNECTED = 1
DOT11_CAPABILITY_PRIVACY = 0x0010
MAX_INTERFACE_COUNT = 256
MAX_BSS_ITEM_COUNT = 4096
MAX_BSS_BUFFER_BYTES = 16 * 1024 * 1024
MAX_INFORMATION_ELEMENT_BYTES = 16 * 1024

CALLBACK = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)


class GUID(ctypes.Structure):
    _fields_ = [
        ("data1", DWORD), ("data2", USHORT), ("data3", USHORT),
        ("data4", UCHAR * 8),
    ]

    def as_uuid(self) -> uuid.UUID:
        return uuid.UUID(bytes_le=ctypes.string_at(ctypes.byref(self), ctypes.sizeof(self)))


class WLAN_SSID(ctypes.Structure):
    _fields_ = [("length", ULONG), ("bytes", UCHAR * 32)]


class WLAN_RATE_SET(ctypes.Structure):
    _fields_ = [("length", ULONG), ("values", USHORT * 126)]


class WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [
        ("ssid", WLAN_SSID),
        ("phy_id", ULONG),
        ("bssid", UCHAR * 6),
        ("bss_type", ULONG),
        ("phy_type", ULONG),
        ("rssi_dbm", LONG),
        ("link_quality", ULONG),
        ("in_reg_domain", BOOLEAN),
        ("beacon_period", USHORT),
        ("ap_timestamp", ULONGLONG),
        ("host_timestamp", ULONGLONG),
        ("capability_information", USHORT),
        ("center_frequency_khz", ULONG),
        ("rate_set", WLAN_RATE_SET),
        ("ie_offset", ULONG),
        ("ie_size", ULONG),
    ]


class WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [
        ("total_size", DWORD),
        ("number_of_items", DWORD),
        ("entries", WLAN_BSS_ENTRY * 1),
    ]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [
        ("guid", GUID),
        ("description", WCHAR16 * 256),
        ("state", DWORD),
    ]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [
        ("number_of_items", DWORD),
        ("index", DWORD),
        ("interfaces", WLAN_INTERFACE_INFO * 1),
    ]


class WLAN_NOTIFICATION_DATA(ctypes.Structure):
    _fields_ = [
        ("source", DWORD),
        ("code", DWORD),
        ("interface_guid", GUID),
        ("data_size", DWORD),
        ("data", ctypes.c_void_p),
    ]


WLAN_NOTIFICATION_CALLBACK = CALLBACK(None, ctypes.POINTER(WLAN_NOTIFICATION_DATA), ctypes.c_void_p)


def _null_notification_callback():
    return WLAN_NOTIFICATION_CALLBACK()


@dataclass(frozen=True)
class WlanInterface:
    guid: str
    description: str
    state_code: int

    @property
    def state_name(self) -> str:
        return {
            0: "not ready", 1: "connected", 2: "ad hoc network formed",
            3: "disconnecting", 4: "disconnected", 5: "associating",
            6: "discovering", 7: "authenticating",
        }.get(self.state_code, f"unknown state ({self.state_code})")


@dataclass(frozen=True)
class ScanResult:
    interface: WlanInterface
    access_points: tuple[AccessPoint, ...]
    completed_at_utc: str


def select_interface(interfaces: tuple[WlanInterface, ...], requested_guid: str | None) -> WlanInterface:
    """Select an explicitly requested adapter, or a unique connected/sole adapter."""
    wanted = None
    if requested_guid is not None:
        try:
            wanted = uuid.UUID(requested_guid)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError("--interface must be a valid Windows interface GUID") from exc
    if not interfaces:
        raise ValueError("no wireless interfaces were found")
    if wanted is not None:
        for interface in interfaces:
            if uuid.UUID(interface.guid) == wanted:
                return interface
        raise ValueError(f"wireless interface GUID {wanted} was not found")

    connected = tuple(item for item in interfaces if item.state_code == WLAN_INTERFACE_STATE_CONNECTED)
    if len(connected) == 1:
        return connected[0]
    if len(interfaces) == 1:
        return interfaces[0]
    options = "; ".join(f"{item.guid} ({item.description}, {item.state_name})" for item in interfaces)
    raise ValueError("wireless interface selection is ambiguous; specify --interface GUID. Available: " + options)


def _decode_utf16(units: Any) -> str:
    return ctypes.string_at(ctypes.addressof(units), ctypes.sizeof(units)).decode("utf-16-le", errors="replace").split("\x00", 1)[0]


def _decode_bss_list_blob(blob: bytes | bytearray | memoryview) -> tuple[AccessPoint, ...]:
    """Decode one bounded WLAN_BSS_LIST allocation, validating every offset first."""
    data = bytes(blob)
    header_size = WLAN_BSS_LIST.entries.offset
    if len(data) < header_size:
        raise ValueError("BSS list is shorter than its header")
    total_size = int.from_bytes(data[0:4], "little")
    item_count = int.from_bytes(data[4:8], "little")
    if total_size != len(data) or total_size > MAX_BSS_BUFFER_BYTES:
        raise ValueError("BSS list total size is inconsistent or exceeds the safety limit")
    if item_count > MAX_BSS_ITEM_COUNT:
        raise ValueError("BSS list item count exceeds the safety limit")
    entry_size = ctypes.sizeof(WLAN_BSS_ENTRY)
    entries_end = header_size + item_count * entry_size
    if entries_end > total_size:
        raise ValueError("BSS list item array exceeds the allocation")

    decoded: list[tuple[WLAN_BSS_ENTRY, bytes]] = []
    ie_regions: list[tuple[int, int]] = []
    for index in range(item_count):
        entry_start = header_size + index * entry_size
        entry = WLAN_BSS_ENTRY.from_buffer_copy(data[entry_start:entry_start + entry_size])
        if entry.ssid.length > len(entry.ssid.bytes):
            raise ValueError(f"BSS entry {index} has an invalid SSID length")
        if entry.rate_set.length > len(entry.rate_set.values):
            raise ValueError(f"BSS entry {index} has an invalid rate-set length")
        if entry.in_reg_domain not in (0, 1):
            raise ValueError(f"BSS entry {index} has an invalid regulatory-domain flag")
        if entry.ie_size > MAX_INFORMATION_ELEMENT_BYTES:
            raise ValueError(f"BSS entry {index} information elements exceed the safety limit")
        if entry.ie_size:
            if entry.ie_offset < entry_size:
                raise ValueError(f"BSS entry {index} information-element offset points inside its structure")
            start = entry_start + entry.ie_offset
            end = start + entry.ie_size
            if start < entries_end or end < start or end > total_size:
                raise ValueError(f"BSS entry {index} information-element range exceeds the allocation")
            ie_regions.append((start, end))
            ies = data[start:end]
        else:
            ies = b""
        decoded.append((entry, ies))

    ordered_regions = sorted(ie_regions)
    if any(current[0] < previous[1] for previous, current in zip(ordered_regions, ordered_regions[1:])):
        raise ValueError("BSS information-element regions overlap")

    access_points: list[AccessPoint] = []
    for index, (entry, ies) in enumerate(decoded):
        try:
            ssid = bytes(entry.ssid.bytes[:entry.ssid.length])
            bssid = ":".join(f"{octet:02x}" for octet in entry.bssid)
            privacy = bool(entry.capability_information & DOT11_CAPABILITY_PRIVACY)
            security = parse_security_information_elements(ies, privacy_enabled=privacy)
            access_points.append(AccessPoint(
                ssid_bytes=ssid,
                bssid=bssid,
                rssi_dbm=int(entry.rssi_dbm),
                signal_quality=int(entry.link_quality),
                center_frequency_khz=int(entry.center_frequency_khz),
                phy_type=int(entry.phy_type),
                capability_information=int(entry.capability_information),
                security=security,
                phy_id=int(entry.phy_id),
                bss_type=int(entry.bss_type),
                beacon_period_tu=int(entry.beacon_period),
                ap_timestamp_us=int(entry.ap_timestamp),
                host_timestamp_us=int(entry.host_timestamp),
                in_regulatory_domain=bool(entry.in_reg_domain),
                supported_rates_raw=tuple(int(rate) for rate in entry.rate_set.values[:entry.rate_set.length]),
                information_elements=ies,
            ))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"BSS entry {index} contains invalid observation data: {exc}") from exc
    return tuple(access_points)


class WlanApiError(RuntimeError):
    def __init__(self, operation: str, code: int | None = None, detail: str | None = None):
        self.operation = operation
        self.code = code
        self.detail = detail
        message = f"{operation} failed"
        if code is not None:
            try:
                message += f" with Windows error {code}: {ctypes.FormatError(code).strip()}"
            except (AttributeError, OSError):
                message += f" with Windows error {code}"
        if code == 5:
            message += ". Check Windows Location privacy settings and allow desktop apps to access location"
        if detail:
            message += f" ({detail})"
        super().__init__(message)


def _load_wlan_api():
    if os.name != "nt":
        raise WlanApiError("live WLAN scanning", detail="the Native Wi-Fi API is available only on Windows")
    try:
        dll = ctypes.WinDLL("wlanapi.dll", use_last_error=True)
    except OSError as exc:
        raise WlanApiError("loading wlanapi.dll", detail=str(exc)) from exc

    dll.WlanOpenHandle.argtypes = [DWORD, ctypes.c_void_p, ctypes.POINTER(DWORD), ctypes.POINTER(HANDLE)]
    dll.WlanOpenHandle.restype = DWORD
    dll.WlanCloseHandle.argtypes = [HANDLE, ctypes.c_void_p]
    dll.WlanCloseHandle.restype = DWORD
    dll.WlanFreeMemory.argtypes = [ctypes.c_void_p]
    dll.WlanFreeMemory.restype = None
    dll.WlanEnumInterfaces.argtypes = [HANDLE, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    dll.WlanEnumInterfaces.restype = DWORD
    dll.WlanScan.argtypes = [HANDLE, ctypes.POINTER(GUID), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    dll.WlanScan.restype = DWORD
    dll.WlanGetNetworkBssList.argtypes = [
        HANDLE, ctypes.POINTER(GUID), ctypes.c_void_p, ULONG, ctypes.c_int32,
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
    ]
    dll.WlanGetNetworkBssList.restype = DWORD
    callback_type = WLAN_NOTIFICATION_CALLBACK
    dll.WlanRegisterNotification.argtypes = [
        HANDLE, DWORD, ctypes.c_int32, callback_type, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.POINTER(DWORD),
    ]
    dll.WlanRegisterNotification.restype = DWORD
    dll._notification_callback_type = callback_type
    return dll


def _check_status(operation: str, status: int) -> None:
    if status:
        raise WlanApiError(operation, int(status))


def _open_client(dll):
    negotiated = DWORD()
    handle = HANDLE()
    status = int(dll.WlanOpenHandle(WLAN_API_VERSION_2, None, ctypes.byref(negotiated), ctypes.byref(handle)))
    if status:
        raise WlanApiError("WlanOpenHandle", status)
    if not handle.value:
        raise WlanApiError("WlanOpenHandle", detail="Windows returned a null client handle")
    return handle, int(negotiated.value)


def _enum_interfaces(dll, handle) -> tuple[WlanInterface, ...]:
    output = ctypes.c_void_p()
    _check_status("WlanEnumInterfaces", dll.WlanEnumInterfaces(handle, None, ctypes.byref(output)))
    if not output.value:
        raise WlanApiError("WlanEnumInterfaces", detail="Windows returned a null interface list")
    try:
        header_size = WLAN_INTERFACE_INFO_LIST.interfaces.offset
        header = ctypes.string_at(output.value, header_size)
        count = int.from_bytes(header[0:4], "little")
        if count > MAX_INTERFACE_COUNT:
            raise WlanApiError("WlanEnumInterfaces", detail="interface count exceeds the safety limit")
        item_size = ctypes.sizeof(WLAN_INTERFACE_INFO)
        allocation_size = header_size + count * item_size
        raw = ctypes.string_at(output.value, allocation_size)
        interfaces: list[WlanInterface] = []
        for index in range(count):
            start = header_size + index * item_size
            item = WLAN_INTERFACE_INFO.from_buffer_copy(raw[start:start + item_size])
            interfaces.append(WlanInterface(
                guid=str(item.guid.as_uuid()),
                description=_decode_utf16(item.description),
                state_code=int(item.state),
            ))
        return tuple(interfaces)
    finally:
        dll.WlanFreeMemory(output)


def list_interfaces() -> tuple[WlanInterface, ...]:
    """Return actual WLAN interfaces reported by Windows, without scanning."""
    dll = _load_wlan_api()
    handle, _ = _open_client(dll)
    try:
        return _enum_interfaces(dll, handle)
    finally:
        dll.WlanCloseHandle(handle, None)


def scan_live(interface_guid: str | None = None, *, timeout_seconds: int = 15) -> ScanResult:
    """Request a native Wi-Fi scan and return its fresh BSSID-level BSS records."""
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
        raise TypeError("scan timeout must be an integer number of seconds")
    if not 1 <= timeout_seconds <= 120:
        raise ValueError("scan timeout must be between 1 and 120 seconds")

    dll = _load_wlan_api()
    handle, _ = _open_client(dll)
    bss_list = ctypes.c_void_p()
    registered = False
    callback_ref = None
    try:
        interfaces = _enum_interfaces(dll, handle)
        interface = select_interface(interfaces, interface_guid)
        native_guid = GUID.from_buffer_copy(uuid.UUID(interface.guid).bytes_le)
        completion = threading.Event()
        outcome: dict[str, int | None] = {"code": None, "reason": None}

        def notification_callback(data_pointer, _context):
            try:
                if not data_pointer:
                    return
                notification = data_pointer.contents
                if not (int(notification.source) & WLAN_NOTIFICATION_SOURCE_ACM):
                    return
                if notification.interface_guid.as_uuid() != uuid.UUID(interface.guid):
                    return
                code = int(notification.code)
                if code == WLAN_NOTIFICATION_ACM_SCAN_COMPLETE:
                    outcome["code"] = code
                    completion.set()
                elif code == WLAN_NOTIFICATION_ACM_SCAN_FAIL:
                    outcome["code"] = code
                    if notification.data and notification.data_size >= ctypes.sizeof(DWORD):
                        outcome["reason"] = int(ctypes.cast(notification.data, ctypes.POINTER(DWORD)).contents.value)
                    completion.set()
            except BaseException:
                # A Python exception must never escape through a native callback frame.
                outcome["code"] = -1
                completion.set()

        callback_ref = dll._notification_callback_type(notification_callback)
        previous_source = DWORD()
        _check_status("WlanRegisterNotification", dll.WlanRegisterNotification(
            handle, WLAN_NOTIFICATION_SOURCE_ACM, 0, callback_ref, None, None, ctypes.byref(previous_source)
        ))
        registered = True
        _check_status("WlanScan", dll.WlanScan(handle, ctypes.byref(native_guid), None, None, None))
        if not completion.wait(timeout_seconds):
            raise WlanApiError("waiting for WLAN scan completion", detail=f"timed out after {timeout_seconds} seconds")
        if outcome["code"] == WLAN_NOTIFICATION_ACM_SCAN_FAIL:
            raise WlanApiError("WLAN scan notification", detail=f"scan failed; reason code {outcome['reason']}")
        if outcome["code"] != WLAN_NOTIFICATION_ACM_SCAN_COMPLETE:
            raise WlanApiError("WLAN scan notification", detail="received an invalid completion callback")

        _check_status("WlanGetNetworkBssList", dll.WlanGetNetworkBssList(
            handle, ctypes.byref(native_guid), None, 1, 0, None, ctypes.byref(bss_list)
        ))
        if not bss_list.value:
            raise WlanApiError("WlanGetNetworkBssList", detail="Windows returned a null BSS list")
        size = int(ctypes.cast(bss_list, ctypes.POINTER(DWORD)).contents.value)
        if size < WLAN_BSS_LIST.entries.offset or size > MAX_BSS_BUFFER_BYTES:
            raise WlanApiError("WlanGetNetworkBssList", detail="BSS allocation size is outside the safety bounds")
        blob = ctypes.string_at(bss_list.value, size)
        try:
            access_points = _decode_bss_list_blob(blob)
        except ValueError as exc:
            raise WlanApiError("decoding WLAN BSS observations", detail=str(exc)) from exc
        timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        return ScanResult(interface, access_points, timestamp)
    finally:
        if registered:
            try:
                dll.WlanRegisterNotification(handle, WLAN_NOTIFICATION_SOURCE_NONE, 0, _null_notification_callback(), None, None, None)
            except (OSError, TypeError):
                pass
        if bss_list.value:
            dll.WlanFreeMemory(bss_list)
        dll.WlanCloseHandle(handle, None)
