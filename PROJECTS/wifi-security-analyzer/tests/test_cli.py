import json

import pytest

from src import cli
from src.ie_parser import parse_security_information_elements
from src.models import AccessPoint
from src.windows_wlan import ScanResult, WlanApiError, WlanInterface


def access_point(ssid=b"lab", bssid="02:11:22:33:44:55"):
    ies = bytes.fromhex("300e0100000fac040100000fac040100000fac020000")
    profile = parse_security_information_elements(ies, privacy_enabled=True)
    return AccessPoint(
        ssid, bssid, -54, 82, 5180000, 8, 0x10, profile,
        phy_id=4, bss_type=1, beacon_period_tu=100, ap_timestamp_us=123456,
        host_timestamp_us=654321, in_regulatory_domain=True, supported_rates_raw=(12, 24, 130),
        information_elements=ies,
    )


def scan(ap=None):
    interface = WlanInterface("11111111-2222-3333-4444-555555555555", "Adapter", 1)
    return ScanResult(interface, (ap or access_point(),), "2026-01-01T00:00:00Z")


def test_json_report_preserves_ssid_bytes_and_escapes_control_text():
    item = access_point(b"lab\n\x1b")
    data = cli.scan_to_dict(scan(item), baseline=None)
    rendered = json.dumps(data, ensure_ascii=True)
    assert data["networks"][0]["access_point"]["ssid_hex"] == "6c61620a1b"
    assert "\\n" in rendered and "\\u001b" in rendered


def test_json_report_includes_raw_information_elements_and_native_fields():
    data = cli.scan_to_dict(scan(), baseline=None)["networks"][0]["access_point"]
    assert data["information_elements_hex"] == access_point().information_elements.hex()
    assert data["phy_id"] == 4
    assert data["host_timestamp_us"] == 654321
    assert data["supported_rates_raw"] == [12, 24, 130]


def test_json_report_contains_assessment_findings_for_each_live_bss():
    item = access_point(bssid="02:11:22:33:44:56")
    data = cli.scan_to_dict(scan(item), baseline=None)
    assert data["observation_count"] == 1
    assert data["networks"][0]["findings"]


def test_scan_timeout_must_be_within_supported_bounds():
    parser = cli.build_parser()
    with pytest.raises(SystemExit) as error:
        parser.parse_args(["scan", "--timeout", "0"])
    assert error.value.code == 2


def test_baseline_creation_requires_explicit_bssid_selection(monkeypatch, capsys, tmp_path):
    called = False
    def unexpected_scan(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("scan must not run before baseline options are validated")
    monkeypatch.setattr(cli.windows_wlan, "scan_live", unexpected_scan)
    with pytest.raises(SystemExit) as error:
        cli.main(["scan", "--create-baseline", str(tmp_path / "baseline.json")])
    assert error.value.code == 2
    assert not called


def test_baseline_creation_uses_only_selected_live_observations(monkeypatch, capsys, tmp_path):
    observed = access_point(bssid="02:11:22:33:44:55")
    other = access_point(bssid="02:11:22:33:44:66")
    monkeypatch.setattr(cli.windows_wlan, "scan_live", lambda *a, **k: ScanResult(scan().interface, (observed, other), scan().completed_at_utc))
    path = tmp_path / "baseline.json"
    assert cli.main(["scan", "--create-baseline", str(path), "--include-bssid", observed.bssid, "--json"]) == 0
    contents = json.loads(path.read_text(encoding="utf-8"))
    assert [item["bssid"] for item in contents["access_points"]] == [observed.bssid]
    assert json.loads(capsys.readouterr().out)["baseline_created"]["entries"] == 1


def test_existing_baseline_is_not_overwritten_without_opt_in(monkeypatch, tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text("preserve", encoding="utf-8")
    monkeypatch.setattr(cli.windows_wlan, "scan_live", lambda *a, **k: (_ for _ in ()).throw(AssertionError("scan should not run")))
    assert cli.main(["scan", "--create-baseline", str(path), "--include-bssid", access_point().bssid]) == 1
    assert path.read_text(encoding="utf-8") == "preserve"


def test_api_denial_is_a_friendly_error_without_traceback(monkeypatch, capsys):
    monkeypatch.setattr(cli.windows_wlan, "scan_live", lambda *a, **k: (_ for _ in ()).throw(WlanApiError("WlanScan", 5)))
    assert cli.main(["scan"]) == 1
    error = capsys.readouterr().err
    assert "Location" in error
    assert "Traceback" not in error


def test_interfaces_json_reports_no_fabricated_adapters(monkeypatch, capsys):
    monkeypatch.setattr(cli.windows_wlan, "list_interfaces", lambda: ())
    assert cli.main(["interfaces", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"interfaces": []}


def test_malformed_interface_guid_is_rejected_during_argument_parsing():
    with pytest.raises(SystemExit) as error:
        cli.build_parser().parse_args(["scan", "--interface", "not-a-guid"])
    assert error.value.code == 2


def test_malformed_baseline_bssid_is_rejected_before_live_scan(monkeypatch, tmp_path):
    monkeypatch.setattr(cli.windows_wlan, "scan_live", lambda *a, **k: (_ for _ in ()).throw(AssertionError("invalid BSSID must not scan")))
    with pytest.raises(SystemExit) as error:
        cli.main(["scan", "--create-baseline", str(tmp_path / "baseline.json"), "--include-bssid", "not-a-bssid"])
    assert error.value.code == 2
