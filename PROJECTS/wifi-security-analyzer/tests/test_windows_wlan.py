import ctypes

import pytest

from src.windows_wlan import (
    WLAN_BSS_ENTRY, WLAN_BSS_LIST, GUID, WlanInterface, _decode_bss_list_blob,
    _null_notification_callback, select_interface,
)


def test_native_bss_entry_layout_matches_wlanapi_abi():
    assert ctypes.sizeof(GUID) == 16
    assert ctypes.sizeof(WLAN_BSS_ENTRY) == 360
    assert WLAN_BSS_ENTRY.phy_id.offset == 36
    assert WLAN_BSS_ENTRY.bssid.offset == 40
    assert WLAN_BSS_ENTRY.bss_type.offset == 48
    assert WLAN_BSS_ENTRY.rssi_dbm.offset == 56
    assert WLAN_BSS_ENTRY.beacon_period.offset == 66
    assert WLAN_BSS_ENTRY.ap_timestamp.offset == 72
    assert WLAN_BSS_ENTRY.capability_information.offset == 88
    assert WLAN_BSS_ENTRY.center_frequency_khz.offset == 92
    assert WLAN_BSS_ENTRY.rate_set.offset == 96
    assert WLAN_BSS_ENTRY.ie_offset.offset == 352
    assert WLAN_BSS_ENTRY.ie_size.offset == 356


def test_native_bss_list_entries_begin_after_two_dword_header():
    assert WLAN_BSS_LIST.entries.offset == 8


def test_explicit_interface_guid_selects_the_exact_interface():
    wanted = WlanInterface("11111111-2222-3333-4444-555555555555", "Wi-Fi", 1)
    other = WlanInterface("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "Wi-Fi 2", 1)
    assert select_interface((wanted, other), wanted.guid) == wanted


def test_one_connected_interface_is_selected_among_inactive_adapters():
    inactive = WlanInterface("11111111-2222-3333-4444-555555555555", "Wi-Fi 2", 4)
    connected = WlanInterface("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "Wi-Fi", 1)
    assert select_interface((inactive, connected), None) == connected


def test_single_disconnected_interface_is_still_selectable_for_scanning():
    interface = WlanInterface("11111111-2222-3333-4444-555555555555", "Wi-Fi", 4)
    assert select_interface((interface,), None) == interface


def test_multiple_connected_interfaces_require_explicit_selection():
    interfaces = (
        WlanInterface("11111111-2222-3333-4444-555555555555", "Wi-Fi", 1),
        WlanInterface("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "Wi-Fi 2", 1),
    )
    with pytest.raises(ValueError, match="--interface"):
        select_interface(interfaces, None)


def test_multiple_inactive_interfaces_are_not_silently_guessed():
    interfaces = (
        WlanInterface("11111111-2222-3333-4444-555555555555", "Wi-Fi", 4),
        WlanInterface("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "Wi-Fi 2", 4),
    )
    with pytest.raises(ValueError, match="--interface"):
        select_interface(interfaces, None)


def test_empty_interface_enumeration_is_reported():
    with pytest.raises(ValueError, match="no wireless interfaces"):
        select_interface((), None)


def test_explicit_unknown_guid_is_not_replaced_by_another_interface():
    interface = WlanInterface("11111111-2222-3333-4444-555555555555", "Wi-Fi", 1)
    with pytest.raises(ValueError, match="not found"):
        select_interface((interface,), "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")


def test_malformed_explicit_guid_is_rejected():
    with pytest.raises(ValueError, match="GUID"):
        select_interface((), "not-a-guid")


def bss_blob(records):
    header_size = WLAN_BSS_LIST.entries.offset
    entry_size = ctypes.sizeof(WLAN_BSS_ENTRY)
    entries_end = header_size + len(records) * entry_size
    ies_total = sum(len(record.get("ies", b"")) for record in records)
    blob = bytearray(entries_end + ies_total)
    offset = 0
    for index, record in enumerate(records):
        entry = WLAN_BSS_ENTRY()
        ssid = record.get("ssid", b"")
        entry.ssid.length = len(ssid)
        for position, octet in enumerate(ssid):
            entry.ssid.bytes[position] = octet
        for position, octet in enumerate(record.get("bssid", bytes.fromhex("021122334455"))):
            entry.bssid[position] = octet
        entry.phy_id = record.get("phy_id", 2)
        entry.bss_type = record.get("bss_type", 1)
        entry.phy_type = record.get("phy_type", 8)
        entry.rssi_dbm = record.get("rssi_dbm", -55)
        entry.link_quality = record.get("link_quality", 80)
        entry.in_reg_domain = record.get("in_reg_domain", 1)
        entry.beacon_period = record.get("beacon_period", 100)
        entry.ap_timestamp = record.get("ap_timestamp", 123456)
        entry.host_timestamp = record.get("host_timestamp", 654321)
        entry.capability_information = record.get("capability_information", 0x10)
        entry.center_frequency_khz = record.get("center_frequency_khz", 5180000)
        rates = record.get("rates", (12, 24, 130))
        entry.rate_set.length = len(rates)
        for position, rate in enumerate(rates):
            entry.rate_set.values[position] = rate
        ies = record.get("ies", b"")
        entry.ie_size = len(ies)
        entry.ie_offset = record.get("ie_offset", entries_end + offset - (header_size + index * entry_size))
        start = header_size + index * entry_size
        blob[start:start + entry_size] = ctypes.string_at(ctypes.byref(entry), entry_size)
        if ies:
            ie_start = start + entry.ie_offset
            blob[ie_start:ie_start + len(ies)] = ies
            offset += len(ies)
    blob[0:4] = len(blob).to_bytes(4, "little")
    blob[4:8] = len(records).to_bytes(4, "little")
    return bytes(blob)


def rsn_ie():
    suite = bytes.fromhex("000fac04")
    body = b"\x01\x00" + suite + b"\x01\x00" + suite + b"\x01\x00" + bytes.fromhex("000fac02") + b"\x00\x00"
    return bytes((48, len(body))) + body


def test_bss_decoder_preserves_live_fields_and_parses_advertised_security():
    blob = bss_blob([{
        "ssid": b"lab", "bssid": bytes.fromhex("021122334455"), "phy_id": 7,
        "bss_type": 1, "rssi_dbm": -61, "link_quality": 73, "center_frequency_khz": 5180000,
        "ies": rsn_ie(),
    }])
    ap = _decode_bss_list_blob(blob)[0]
    assert ap.ssid_bytes == b"lab"
    assert ap.bssid == "02:11:22:33:44:55"
    assert (ap.phy_id, ap.bss_type, ap.rssi_dbm, ap.signal_quality) == (7, 1, -61, 73)
    assert ap.beacon_period_tu == 100
    assert ap.ap_timestamp_us == 123456 and ap.host_timestamp_us == 654321
    assert ap.in_regulatory_domain is True
    assert ap.supported_rates_raw == (12, 24, 130)
    assert ap.security.protocols == ("RSN",)
    assert ap.information_elements == rsn_ie()


def test_bss_decoder_accepts_a_real_empty_scan_result():
    assert _decode_bss_list_blob((8).to_bytes(4, "little") + b"\x00\x00\x00\x00") == ()


def test_bss_decoder_rejects_item_array_outside_declared_allocation():
    blob = (8).to_bytes(4, "little") + (1).to_bytes(4, "little")
    with pytest.raises(ValueError, match="item array"):
        _decode_bss_list_blob(blob)


def test_bss_decoder_rejects_ssid_length_outside_native_buffer():
    entry = {"ssid": b"x"}
    blob = bytearray(bss_blob([entry]))
    blob[8:12] = (33).to_bytes(4, "little")
    with pytest.raises(ValueError, match="SSID length"):
        _decode_bss_list_blob(blob)


def test_bss_decoder_rejects_rate_count_outside_native_buffer():
    blob = bytearray(bss_blob([{}]))
    rate_count_offset = WLAN_BSS_LIST.entries.offset + WLAN_BSS_ENTRY.rate_set.offset
    blob[rate_count_offset:rate_count_offset + 4] = (127).to_bytes(4, "little")
    with pytest.raises(ValueError, match="rate-set length"):
        _decode_bss_list_blob(blob)


def test_bss_decoder_rejects_ie_offset_into_the_entry_structure():
    blob = bytearray(bss_blob([{"ies": rsn_ie()}]))
    offset = WLAN_BSS_LIST.entries.offset + WLAN_BSS_ENTRY.ie_offset.offset
    blob[offset:offset + 4] = (1).to_bytes(4, "little")
    with pytest.raises(ValueError, match="inside its structure"):
        _decode_bss_list_blob(blob)


def test_bss_decoder_rejects_ie_extent_past_allocation():
    blob = bytearray(bss_blob([{"ies": rsn_ie()}]))
    offset = WLAN_BSS_LIST.entries.offset + WLAN_BSS_ENTRY.ie_offset.offset
    blob[offset:offset + 4] = (ctypes.sizeof(WLAN_BSS_ENTRY) + 1).to_bytes(4, "little")
    with pytest.raises(ValueError, match="exceeds the allocation"):
        _decode_bss_list_blob(blob)


def test_bss_decoder_rejects_overlapping_ie_regions():
    first = {"ies": rsn_ie()}
    second = {"ies": rsn_ie(), "ie_offset": ctypes.sizeof(WLAN_BSS_ENTRY)}
    with pytest.raises(ValueError, match="overlap"):
        _decode_bss_list_blob(bss_blob([first, second]))


def test_notification_unregistration_uses_a_typed_null_callback():
    callback = _null_notification_callback()
    assert not bool(callback)
