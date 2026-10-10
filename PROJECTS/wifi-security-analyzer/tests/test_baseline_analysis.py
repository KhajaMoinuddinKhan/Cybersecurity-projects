from datetime import datetime, timezone
import json

import pytest

from src.analysis import analyze_access_points
from src.baseline import (
    baseline_from_dict, baseline_to_dict, build_baseline, read_baseline, write_baseline,
)
from src.ie_parser import parse_security_information_elements
from src.models import AccessPoint


def element(element_id, payload):
    return bytes((element_id, len(payload))) + payload


def suite(number):
    return bytes.fromhex("000fac") + bytes((number,))


def rsn(akms=(2,), pairwise=(4,), capabilities=0):
    body = b"\x01\x00" + suite(4) + len(pairwise).to_bytes(2, "little")
    body += b"".join(suite(item) for item in pairwise)
    body += len(akms).to_bytes(2, "little") + b"".join(suite(item) for item in akms)
    body += capabilities.to_bytes(2, "little")
    return element(48, body)


def ap(*, ssid=b"lab", bssid="02:00:00:00:00:01", ies=None, privacy=True):
    if ies is None:
        ies = rsn()
    return AccessPoint(ssid, bssid, -50, 75, 5180000, 8, 0x10 if privacy else 0,
                       parse_security_information_elements(ies, privacy_enabled=privacy))


def timestamp():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def test_baseline_requires_at_least_one_explicit_observed_bssid():
    with pytest.raises(ValueError, match="include at least one"):
        build_baseline([ap()], [])


def test_baseline_only_contains_bssids_explicitly_selected_by_user():
    first = ap(bssid="02:00:00:00:00:01")
    second = ap(bssid="02:00:00:00:00:02")
    baseline = build_baseline([first, second], [second.bssid])
    assert [entry.bssid for entry in baseline.access_points] == [second.bssid]


def test_baseline_rejects_an_included_bssid_not_seen_in_the_live_scan():
    with pytest.raises(ValueError, match="not present in the scan"):
        build_baseline([ap()], ["02:00:00:00:00:ff"])


def test_baseline_rejects_duplicate_observations_that_conflict_for_one_bssid():
    first = ap(bssid="02:00:00:00:00:01")
    changed = ap(ssid=b"other", bssid="02:00:00:00:00:01")
    with pytest.raises(ValueError, match="conflicting observations"):
        build_baseline([first, changed], [first.bssid])


def test_baseline_round_trip_preserves_real_observation_attributes():
    original = ap(ssid=b"a\x00b", bssid="02:00:00:00:00:01")
    baseline = build_baseline([original], [original.bssid], created_at=timestamp())
    restored = baseline_from_dict(baseline_to_dict(baseline))
    assert restored == baseline
    entry = restored.access_points[0]
    assert entry.ssid_hex == original.ssid_hex
    assert entry.security.protocols == original.security.protocols


def test_baseline_timestamp_is_generated_when_not_supplied():
    before = datetime.now(timezone.utc)
    baseline = build_baseline([ap()], ["02:00:00:00:00:01"])
    created = datetime.fromisoformat(baseline.created_at.replace("Z", "+00:00"))
    assert before <= created <= datetime.now(timezone.utc)


def test_baseline_json_round_trip_uses_json_safe_dynamic_data():
    baseline = build_baseline([ap()], ["02:00:00:00:00:01"], created_at=timestamp())
    serialized = json.dumps(baseline_to_dict(baseline))
    assert baseline_from_dict(json.loads(serialized)) == baseline


def test_baseline_rejects_unknown_schema_version():
    value = baseline_to_dict(build_baseline([ap()], ["02:00:00:00:00:01"], created_at=timestamp()))
    value["schema_version"] = 99
    with pytest.raises(ValueError, match="schema version"):
        baseline_from_dict(value)


def test_baseline_rejects_missing_observation_fields():
    value = baseline_to_dict(build_baseline([ap()], ["02:00:00:00:00:01"], created_at=timestamp()))
    del value["access_points"][0]["ssid_hex"]
    with pytest.raises(ValueError, match="ssid_hex"):
        baseline_from_dict(value)


def test_baseline_rejects_invalid_ssid_hex():
    value = baseline_to_dict(build_baseline([ap()], ["02:00:00:00:00:01"], created_at=timestamp()))
    value["access_points"][0]["ssid_hex"] = "xyz"
    with pytest.raises(ValueError, match="ssid_hex"):
        baseline_from_dict(value)


def test_baseline_rejects_invalid_timestamp():
    value = baseline_to_dict(build_baseline([ap()], ["02:00:00:00:00:01"], created_at=timestamp()))
    value["created_at"] = "not-a-time"
    with pytest.raises(ValueError, match="created_at"):
        baseline_from_dict(value)


def test_baseline_rejects_duplicate_bssid_entries():
    value = baseline_to_dict(build_baseline([ap()], ["02:00:00:00:00:01"], created_at=timestamp()))
    value["access_points"].append(dict(value["access_points"][0]))
    with pytest.raises(ValueError, match="duplicate BSSID"):
        baseline_from_dict(value)


def test_baseline_file_is_not_overwritten_without_explicit_permission(tmp_path):
    baseline = build_baseline([ap()], ["02:00:00:00:00:01"], created_at=timestamp())
    path = tmp_path / "approved.json"
    write_baseline(path, baseline)
    with pytest.raises(FileExistsError):
        write_baseline(path, baseline)
    assert read_baseline(path) == baseline


def test_baseline_file_can_be_replaced_only_when_requested(tmp_path):
    first = build_baseline([ap()], ["02:00:00:00:00:01"], created_at=timestamp())
    second_ap = ap(bssid="02:00:00:00:00:02")
    second = build_baseline([second_ap], [second_ap.bssid], created_at=timestamp())
    path = tmp_path / "approved.json"
    write_baseline(path, first)
    write_baseline(path, second, overwrite=True)
    assert read_baseline(path) == second


def test_invalid_baseline_file_is_rejected_not_replaced_with_empty_baseline(tmp_path):
    path = tmp_path / "approved.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON"):
        read_baseline(path)


def test_unrecognized_bssid_for_baselined_ssid_is_caveated():
    known = ap(bssid="02:00:00:00:00:01")
    baseline = build_baseline([known], [known.bssid], created_at=timestamp())
    new = ap(bssid="02:00:00:00:00:02")
    assessment = analyze_access_points([new], baseline=baseline)[0]
    finding = next(item for item in assessment.findings if item.code == "UNRECOGNIZED_BSSID")
    assert finding.severity == "MEDIUM"
    assert "legitimate" in finding.message.lower()


def test_different_ssid_does_not_become_rogue_only_for_unknown_bssid():
    known = ap(ssid=b"approved", bssid="02:00:00:00:00:01")
    baseline = build_baseline([known], [known.bssid], created_at=timestamp())
    unrelated = ap(ssid=b"unrelated", bssid="02:00:00:00:00:02")
    codes = {item.code for item in analyze_access_points([unrelated], baseline=baseline)[0].findings}
    assert "UNRECOGNIZED_BSSID" not in codes


def test_same_bssid_with_security_downgrade_is_high_severity():
    approved = ap(bssid="02:00:00:00:00:01")
    baseline = build_baseline([approved], [approved.bssid], created_at=timestamp())
    open_ap = ap(bssid=approved.bssid, ies=b"", privacy=False)
    findings = analyze_access_points([open_ap], baseline=baseline)[0].findings
    downgrade = next(item for item in findings if item.code == "SECURITY_DOWNGRADE")
    assert downgrade.severity == "HIGH"


def test_profile_change_that_is_not_proven_downgrade_is_reported_cautiously():
    approved = ap(bssid="02:00:00:00:00:01")
    baseline = build_baseline([approved], [approved.bssid], created_at=timestamp())
    upgraded = ap(bssid=approved.bssid, ies=rsn(akms=(8,)), privacy=True)
    findings = analyze_access_points([upgraded], baseline=baseline)[0].findings
    assert any(item.code == "SECURITY_PROFILE_CHANGED" for item in findings)
    assert not any(item.code == "SECURITY_DOWNGRADE" for item in findings)


def test_hidden_ssids_do_not_group_unrelated_bssids_into_an_evil_twin_candidate():
    known = ap(ssid=b"", bssid="02:00:00:00:00:01")
    baseline = build_baseline([known], [known.bssid], created_at=timestamp())
    hidden = ap(ssid=b"", bssid="02:00:00:00:00:02")
    codes = {item.code for item in analyze_access_points([hidden], baseline=baseline)[0].findings}
    assert "UNRECOGNIZED_BSSID" not in codes


def test_baseline_does_not_replace_an_explicit_empty_timestamp_with_current_time():
    with pytest.raises(ValueError, match="created_at"):
        build_baseline([ap()], ["02:00:00:00:00:01"], created_at="")


def test_baseline_rejects_whitespace_inside_ssid_hex_encoding():
    value = baseline_to_dict(build_baseline([ap()], ["02:00:00:00:00:01"], created_at=timestamp()))
    value["access_points"][0]["ssid_hex"] = "6c 61 62"
    with pytest.raises(ValueError, match="ssid_hex"):
        baseline_from_dict(value)
