from __future__ import annotations

import pytest

from src.ie_parser import parse_security_information_elements


RSN_OUI = bytes.fromhex("000fac")
WPA_OUI = bytes.fromhex("0050f2")


def element(element_id: int, body: bytes) -> bytes:
    return bytes((element_id, len(body))) + body


def suite(selector: int, oui: bytes = RSN_OUI) -> bytes:
    return oui + bytes((selector,))


def rsn_ie(*, akms=(2,), pairwise=(4,), group=4, capabilities=0, version=1) -> bytes:
    body = version.to_bytes(2, "little") + suite(group)
    body += len(pairwise).to_bytes(2, "little")
    body += b"".join(suite(value) for value in pairwise)
    body += len(akms).to_bytes(2, "little")
    body += b"".join(suite(value) for value in akms)
    body += capabilities.to_bytes(2, "little")
    return element(48, body)


def wpa_ie(*, akms=(2,), pairwise=(4,), group=4) -> bytes:
    body = WPA_OUI + b"\x01" + b"\x01\x00" + suite(group, WPA_OUI)
    body += len(pairwise).to_bytes(2, "little")
    body += b"".join(suite(value, WPA_OUI) for value in pairwise)
    body += len(akms).to_bytes(2, "little")
    body += b"".join(suite(value, WPA_OUI) for value in akms)
    return element(221, body)


def test_empty_information_elements_with_no_privacy_are_open():
    result = parse_security_information_elements(b"", privacy_enabled=False)
    assert result.security_label == "Open"
    assert result.protocols == ()
    assert result.parse_errors == ()


def test_privacy_bit_without_security_ie_is_not_misreported_as_open():
    result = parse_security_information_elements(b"", privacy_enabled=True)
    assert result.security_label == "WEP or unknown legacy privacy"


def test_rsn_psk_and_ccmp_are_reported_as_wpa2_personal():
    result = parse_security_information_elements(rsn_ie(), privacy_enabled=True)
    assert result.security_label == "WPA2-Personal"
    assert result.protocols == ("RSN",)
    assert result.authentication_suites == ("PSK",)
    assert result.pairwise_ciphers == ("CCMP-128",)
    assert result.group_ciphers == ("CCMP-128",)


def test_rsn_sae_is_reported_as_wpa3_personal():
    result = parse_security_information_elements(rsn_ie(akms=(8,)), privacy_enabled=True)
    assert result.security_label == "WPA3-Personal"
    assert result.authentication_suites == ("SAE",)


def test_psk_and_sae_are_reported_as_transition_mode():
    result = parse_security_information_elements(rsn_ie(akms=(2, 8)), privacy_enabled=True)
    assert result.security_label == "WPA2/WPA3 transition"


def test_owe_is_reported_as_enhanced_open_not_unsecured_open():
    result = parse_security_information_elements(rsn_ie(akms=(18,)), privacy_enabled=False)
    assert result.security_label == "Enhanced Open (OWE)"
    assert result.protocols == ("RSN",)


def test_enterprise_akm_is_reported_separately_from_personal_psk():
    result = parse_security_information_elements(rsn_ie(akms=(1,)), privacy_enabled=True)
    assert result.security_label == "WPA2-Enterprise"
    assert result.authentication_suites == ("802.1X",)


def test_unknown_akm_is_preserved_as_its_selector_instead_of_guessed():
    result = parse_security_information_elements(rsn_ie(akms=(153,)), privacy_enabled=True)
    assert result.authentication_suites == ("00:0f:ac:99",)
    assert result.security_label == "RSN-secured (authentication unresolved)"


def test_tkip_cipher_is_preserved_for_security_assessment():
    result = parse_security_information_elements(rsn_ie(pairwise=(2,), group=2), privacy_enabled=True)
    assert result.pairwise_ciphers == ("TKIP",)
    assert result.group_ciphers == ("TKIP",)


def test_wep_suites_are_identified_from_the_rsn_selector():
    result = parse_security_information_elements(rsn_ie(pairwise=(1, 5), group=5), privacy_enabled=True)
    assert result.pairwise_ciphers == ("WEP-40", "WEP-104")
    assert result.group_ciphers == ("WEP-104",)


def test_wps_vendor_element_is_detected_without_claiming_exploitability():
    wps = element(221, WPA_OUI + b"\x04\x10\x4a\x00\x01")
    result = parse_security_information_elements(rsn_ie() + wps, privacy_enabled=True)
    assert result.wps_advertised is True
    assert "vulnerable" not in result.security_label.lower()


def test_unrelated_vendor_element_is_not_mistaken_for_wps():
    vendor = element(221, bytes.fromhex("aabbcc04") + b"\x10\x4a\x00\x01")
    result = parse_security_information_elements(rsn_ie() + vendor, privacy_enabled=True)
    assert result.wps_advertised is False


def test_wpa_vendor_element_is_recognized_as_legacy_wpa():
    result = parse_security_information_elements(wpa_ie(), privacy_enabled=True)
    assert result.protocols == ("WPA",)
    assert result.security_label == "WPA (legacy)"
    assert result.authentication_suites == ("PSK",)


def test_both_wpa_and_rsn_elements_are_retained():
    result = parse_security_information_elements(wpa_ie() + rsn_ie(), privacy_enabled=True)
    assert result.protocols == ("WPA", "RSN")


def test_pmf_capability_bits_are_decoded_independently():
    result = parse_security_information_elements(rsn_ie(capabilities=(1 << 7)), privacy_enabled=True)
    assert result.pmf_capable is True
    assert result.pmf_required is False


def test_pmf_required_bit_is_reported():
    result = parse_security_information_elements(rsn_ie(capabilities=(1 << 7) | (1 << 6)), privacy_enabled=True)
    assert result.pmf_capable is True
    assert result.pmf_required is True


def test_absent_rsn_capabilities_are_unknown_not_false():
    full = rsn_ie()
    # The capabilities field is optional in the RSN information element.
    without_capabilities = full[:-2]
    result = parse_security_information_elements(without_capabilities, privacy_enabled=True)
    assert result.pmf_capable is None
    assert result.pmf_required is None


def test_truncated_element_header_is_reported_and_never_treated_as_open():
    result = parse_security_information_elements(b"\x30", privacy_enabled=False)
    assert result.parse_errors
    assert result.security_label == "Unknown (malformed security information)"


def test_truncated_element_body_is_reported():
    result = parse_security_information_elements(b"\x30\x08\x01\x00", privacy_enabled=False)
    assert any("length" in error.lower() for error in result.parse_errors)


def test_wrong_rsn_version_is_rejected_without_raising():
    result = parse_security_information_elements(rsn_ie(version=2), privacy_enabled=True)
    assert result.parse_errors
    assert result.security_label == "Unknown (malformed security information)"


def test_rsn_pairwise_count_cannot_read_past_ie():
    body = b"\x01\x00" + suite(4) + b"\x02\x00" + suite(4) + b"\x01\x00" + suite(2)
    result = parse_security_information_elements(element(48, body), privacy_enabled=True)
    assert result.parse_errors


def test_rsn_akm_count_cannot_read_past_ie():
    body = b"\x01\x00" + suite(4) + b"\x01\x00" + suite(4) + b"\x02\x00" + suite(2)
    result = parse_security_information_elements(element(48, body), privacy_enabled=True)
    assert result.parse_errors


def test_duplicate_rsn_elements_are_reported_as_ambiguous():
    result = parse_security_information_elements(rsn_ie() + rsn_ie(akms=(8,)), privacy_enabled=True)
    assert result.parse_errors
    assert result.security_label == "Unknown (malformed security information)"


def test_unknown_oui_is_retained_for_cipher_analysis():
    result = parse_security_information_elements(rsn_ie(pairwise=(4,)), privacy_enabled=True)
    assert result.pairwise_ciphers == ("CCMP-128",)


def test_non_bytes_input_is_rejected_at_the_boundary():
    with pytest.raises(TypeError):
        parse_security_information_elements("not bytes", privacy_enabled=False)


@pytest.mark.parametrize(
    ("akm", "expected"),
    [(3, "FT-802.1X"), (4, "FT-PSK"), (5, "802.1X-SHA256"), (6, "PSK-SHA256"), (9, "FT-SAE")],
)
def test_standard_akm_names_are_decoded(akm, expected):
    result = parse_security_information_elements(rsn_ie(akms=(akm,)), privacy_enabled=True)
    assert result.authentication_suites == (expected,)


@pytest.mark.parametrize(
    ("cipher", "expected"),
    [(8, "GCMP-128"), (9, "GCMP-256"), (10, "CCMP-256")],
)
def test_modern_cipher_names_are_decoded(cipher, expected):
    result = parse_security_information_elements(rsn_ie(pairwise=(cipher,)), privacy_enabled=True)
    assert result.pairwise_ciphers == (expected,)
