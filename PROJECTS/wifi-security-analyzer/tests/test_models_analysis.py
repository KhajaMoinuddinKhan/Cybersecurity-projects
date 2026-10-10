import pytest

from src.analysis import analyze_access_points
from src.ie_parser import parse_security_information_elements
from src.models import AccessPoint


def ie(element_id, payload):
    return bytes((element_id, len(payload))) + payload


def suite(number):
    return bytes.fromhex("000fac") + bytes((number,))


def rsn(akms=(2,), pairwise=(4,), capabilities=0):
    body = b"\x01\x00" + suite(4) + len(pairwise).to_bytes(2, "little")
    body += b"".join(suite(item) for item in pairwise)
    body += len(akms).to_bytes(2, "little") + b"".join(suite(item) for item in akms)
    body += capabilities.to_bytes(2, "little")
    return ie(48, body)


def access_point(*, ssid=b"lab", bssid="02:00:00:00:00:01", rssi=-55, quality=80, frequency=5180000, ies=None, privacy=True):
    if ies is None:
        ies = rsn()
    profile = parse_security_information_elements(ies, privacy_enabled=privacy)
    return AccessPoint(
        ssid_bytes=ssid, bssid=bssid, rssi_dbm=rssi, signal_quality=quality,
        center_frequency_khz=frequency, phy_type=8, capability_information=(0x10 if privacy else 0),
        security=profile,
    )


def test_access_point_normalizes_bssid_case():
    ap = access_point(bssid="02:AA:bb:00:00:01")
    assert ap.bssid == "02:aa:bb:00:00:01"


def test_access_point_preserves_raw_ssid_bytes_for_identity():
    ap = access_point(ssid=b"\xff\x00name")
    assert ap.ssid_hex == "ff006e616d65"


def test_access_point_rejects_ssid_larger_than_protocol_limit():
    with pytest.raises(ValueError, match="SSID"):
        access_point(ssid=b"x" * 33)


def test_access_point_rejects_invalid_bssid():
    with pytest.raises(ValueError, match="BSSID"):
        access_point(bssid="not-a-mac")


def test_access_point_rejects_out_of_range_rssi():
    with pytest.raises(ValueError, match="RSSI"):
        access_point(rssi=1)


def test_access_point_rejects_out_of_range_signal_quality():
    with pytest.raises(ValueError, match="signal quality"):
        access_point(quality=101)


def test_access_point_rejects_missing_security_profile():
    with pytest.raises(TypeError):
        AccessPoint(b"x", "02:00:00:00:00:01", -40, 50, 5180000, 8, 0, None)


def codes_for(ap):
    return {finding.code: finding for finding in analyze_access_points([ap])[0].findings}


def test_open_network_is_flagged_from_security_attributes():
    ap = access_point(ies=b"", privacy=False)
    assert codes_for(ap)["OPEN_NETWORK"].severity == "MEDIUM"


def test_unrecognized_legacy_privacy_is_not_called_open_or_wep():
    ap = access_point(ies=b"", privacy=True)
    findings = codes_for(ap)
    assert "LEGACY_PRIVACY_UNKNOWN" in findings
    assert "OPEN_NETWORK" not in findings
    assert findings["LEGACY_PRIVACY_UNKNOWN"].severity == "MEDIUM"


def test_legacy_wep_cipher_is_high_severity():
    ap = access_point(ies=rsn(pairwise=(1,)), privacy=True)
    assert codes_for(ap)["LEGACY_CIPHER"].severity == "HIGH"


def test_tkip_group_cipher_is_high_severity():
    ap = access_point(ies=rsn(pairwise=(4,), capabilities=0), privacy=True)
    # A group TKIP selector is parsed independently from the pairwise list.
    body = b"\x01\x00" + suite(2) + b"\x01\x00" + suite(4) + b"\x01\x00" + suite(2) + b"\x00\x00"
    tkip = access_point(ies=ie(48, body), privacy=True)
    assert codes_for(tkip)["LEGACY_CIPHER"].severity == "HIGH"


def test_legacy_wpa_only_is_high_severity():
    body = bytes.fromhex("0050f201") + b"\x01\x00" + bytes.fromhex("0050f202")
    body += b"\x01\x00" + bytes.fromhex("0050f204") + b"\x01\x00" + bytes.fromhex("0050f202")
    ap = access_point(ies=ie(221, body), privacy=True)
    assert codes_for(ap)["LEGACY_WPA"].severity == "HIGH"


def test_wps_is_observation_not_a_vulnerability_claim():
    wps = ie(221, bytes.fromhex("0050f204") + b"\x10\x4a\x00\x01")
    ap = access_point(ies=rsn() + wps, privacy=True)
    finding = codes_for(ap)["WPS_ADVERTISED"]
    assert finding.severity == "INFO"
    assert "advertis" in finding.message.lower()


def test_pmf_not_advertised_is_informational_not_a_vulnerability_claim():
    ap = access_point(ies=rsn(capabilities=0), privacy=True)
    finding = codes_for(ap)["PMF_NOT_ADVERTISED"]
    assert finding.severity == "INFO"


def test_malformed_security_element_is_not_misreported_as_open():
    ap = access_point(ies=b"\x30", privacy=False)
    codes = codes_for(ap)
    assert "MALFORMED_SECURITY_IE" in codes
    assert "OPEN_NETWORK" not in codes


def test_security_assessment_does_not_depend_on_ssid_text():
    ordinary = access_point(ssid=b"guest", ies=b"", privacy=False)
    renamed = access_point(ssid=b"Corporate Secure", bssid="02:00:00:00:00:02", ies=b"", privacy=False)
    assert codes_for(ordinary).keys() == codes_for(renamed).keys()


def test_no_baseline_means_no_rogue_ap_claim():
    ap = access_point()
    codes = codes_for(ap)
    assert "UNRECOGNIZED_BSSID" not in codes


def test_empty_live_scan_is_a_valid_empty_assessment():
    assert analyze_access_points([]) == ()


def test_access_point_preserves_all_optional_live_bss_metadata():
    ap = access_point()
    enriched = AccessPoint(
        ap.ssid_bytes, ap.bssid, ap.rssi_dbm, ap.signal_quality, ap.center_frequency_khz,
        ap.phy_type, ap.capability_information, ap.security,
        phy_id=2, bss_type=1, beacon_period_tu=100, ap_timestamp_us=123456,
        host_timestamp_us=987654, in_regulatory_domain=True, supported_rates_raw=(12, 24, 130),
    )
    assert enriched.phy_id == 2
    assert enriched.bss_type == 1
    assert enriched.beacon_period_tu == 100
    assert enriched.ap_timestamp_us == 123456
    assert enriched.host_timestamp_us == 987654
    assert enriched.in_regulatory_domain is True
    assert enriched.supported_rates_raw == (12, 24, 130)


def test_access_point_rejects_non_boolean_regulatory_domain_flag():
    ap = access_point()
    with pytest.raises(TypeError, match="regulatory"):
        AccessPoint(ap.ssid_bytes, ap.bssid, ap.rssi_dbm, ap.signal_quality,
                    ap.center_frequency_khz, ap.phy_type, ap.capability_information, ap.security,
                    in_regulatory_domain=1)


def test_access_point_rejects_rate_set_larger_than_native_capacity():
    ap = access_point()
    with pytest.raises(ValueError, match="rate"):
        AccessPoint(ap.ssid_bytes, ap.bssid, ap.rssi_dbm, ap.signal_quality,
                    ap.center_frequency_khz, ap.phy_type, ap.capability_information, ap.security,
                    supported_rates_raw=(0,) * 127)


def test_access_point_rejects_boolean_as_a_native_unsigned_integer():
    ap = access_point()
    with pytest.raises(TypeError, match="beacon"):
        AccessPoint(ap.ssid_bytes, ap.bssid, ap.rssi_dbm, ap.signal_quality,
                    ap.center_frequency_khz, ap.phy_type, ap.capability_information, ap.security,
                    beacon_period_tu=True)


def test_access_point_preserves_zero_frequency_as_an_observed_unknown():
    ap = access_point(frequency=0)
    assert ap.center_frequency_khz == 0


def test_access_point_preserves_native_rssi_unknown_sentinel():
    ap = access_point(rssi=-128)
    assert ap.rssi_dbm == -128


@pytest.mark.parametrize("bssid", ["00:00:00:00:00:00", "01:00:00:00:00:01"])
def test_access_point_rejects_non_unicast_or_all_zero_bssid(bssid):
    with pytest.raises(ValueError, match="unicast"):
        access_point(bssid=bssid)
