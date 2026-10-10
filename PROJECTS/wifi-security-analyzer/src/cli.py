"""Command-line entry point for live Windows Wi-Fi assessment."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import uuid
from typing import Any

from .analysis import analyze_access_points
from .baseline import baseline_to_dict, build_baseline, read_baseline, write_baseline
from .channels import channel_details
from .models import AccessPoint, Finding, normalize_bssid
from . import windows_wlan


def _timeout(value: str) -> int:
    try:
        number = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be an integer number of seconds") from exc
    if not 1 <= number <= 120:
        raise argparse.ArgumentTypeError("timeout must be between 1 and 120 seconds")
    return number


def _interface_guid(value: str) -> str:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise argparse.ArgumentTypeError("interface must be a valid Windows GUID") from exc
    return value


def _baseline_bssid(value: str) -> str:
    try:
        normalize_bssid(value)
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wifi-security-analyzer",
        description="Assess live Wi-Fi BSS advertisements through the Windows Native Wi-Fi API.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    interfaces = commands.add_parser("interfaces", help="list Windows wireless adapters")
    interfaces.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    scan = commands.add_parser("scan", help="request a live scan and assess observed access points")
    scan.add_argument("--interface", type=_interface_guid, metavar="GUID", help="select an adapter by its Windows interface GUID")
    scan.add_argument("--timeout", type=_timeout, default=15, metavar="SECONDS", help="scan-completion timeout (1–120; default: 15)")
    baseline_group = scan.add_mutually_exclusive_group()
    baseline_group.add_argument("--baseline", type=Path, help="compare live observations with an operator-created baseline")
    baseline_group.add_argument("--create-baseline", type=Path, help="create a baseline from this scan; requires --include-bssid")
    scan.add_argument("--include-bssid", type=_baseline_bssid, action="append", default=[], metavar="BSSID", help="explicit BSSID to include in a new baseline; repeat as needed")
    scan.add_argument("--overwrite-baseline", action="store_true", help="replace an existing baseline only when creating one")
    scan.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def _security_dict(profile) -> dict[str, Any]:
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


def _finding_dict(finding: Finding) -> dict[str, Any]:
    return {
        "code": finding.code,
        "severity": finding.severity,
        "message": finding.message,
        "evidence": list(finding.evidence),
    }


def _access_point_dict(access_point: AccessPoint) -> dict[str, Any]:
    band, channel = channel_details(access_point.center_frequency_khz)
    return {
        "ssid": access_point.ssid_text,
        "ssid_hex": access_point.ssid_hex,
        "bssid": access_point.bssid,
        "rssi_dbm": access_point.rssi_dbm,
        "signal_quality_percent": access_point.signal_quality,
        "center_frequency_khz": access_point.center_frequency_khz,
        "band": band,
        "channel": channel,
        "phy_id": access_point.phy_id,
        "phy_type": access_point.phy_type,
        "bss_type": access_point.bss_type,
        "beacon_period_tu": access_point.beacon_period_tu,
        "ap_timestamp_us": access_point.ap_timestamp_us,
        "host_timestamp_us": access_point.host_timestamp_us,
        "in_regulatory_domain": access_point.in_regulatory_domain,
        "capability_information": access_point.capability_information,
        "supported_rates_raw": list(access_point.supported_rates_raw),
        "information_elements_hex": access_point.information_elements.hex(),
        "security": _security_dict(access_point.security),
    }


def scan_to_dict(scan: windows_wlan.ScanResult, baseline=None) -> dict[str, Any]:
    assessments = analyze_access_points(scan.access_points, baseline=baseline)
    if len(assessments) != len(scan.access_points):
        raise ValueError("assessment count does not match the live scan")
    return {
        "schema_version": 1,
        "scan_completed_at_utc": scan.completed_at_utc,
        "interface": {
            "guid": scan.interface.guid,
            "description": scan.interface.description,
            "state": scan.interface.state_name,
            "state_code": scan.interface.state_code,
        },
        "observation_count": len(scan.access_points),
        "networks": [
            {
                "access_point": _access_point_dict(assessment.access_point),
                "findings": [_finding_dict(finding) for finding in assessment.findings],
            }
            for assessment in assessments
        ],
    }


def _interfaces_to_dict(interfaces) -> dict[str, Any]:
    return {"interfaces": [
        {"guid": item.guid, "description": item.description, "state": item.state_name, "state_code": item.state_code}
        for item in interfaces
    ]}


def _print_interfaces(interfaces) -> None:
    if not interfaces:
        print("No wireless interfaces were reported by Windows.")
        return
    for item in interfaces:
        print(f"{item.description!r} | {item.guid} | {item.state_name}")


def _print_scan(scan: windows_wlan.ScanResult, report: dict[str, Any], baseline_created: int | None) -> None:
    print(f"Adapter: {scan.interface.description!r} ({scan.interface.guid}; {scan.interface.state_name})")
    print(f"Scan completed (UTC): {scan.completed_at_utc}")
    print(f"Observed BSS entries: {len(scan.access_points)}")
    if not scan.access_points:
        print("Windows reported no access points in this scan; this is not an all-clear claim.")
    for network in report["networks"]:
        ap = network["access_point"]
        print(
            f"SSID {json.dumps(ap['ssid'], ensure_ascii=True)} [{ap['ssid_hex'] or 'hidden'}] | "
            f"BSSID {ap['bssid']} | {ap['band']} channel {ap['channel']} | "
            f"RSSI {ap['rssi_dbm']} dBm | {ap['security']['security_label']}"
        )
        for finding in network["findings"]:
            print(f"  {finding['severity']} {finding['code']}: {finding['message']}")
            for evidence in finding["evidence"]:
                print(f"    Evidence: {evidence}")
    if baseline_created is not None:
        print(f"Created operator-selected baseline entries: {baseline_created}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "interfaces":
            interfaces = windows_wlan.list_interfaces()
            if args.json:
                print(json.dumps(_interfaces_to_dict(interfaces), ensure_ascii=True, indent=2))
            else:
                _print_interfaces(interfaces)
            return 0

        if args.include_bssid and args.create_baseline is None:
            parser.error("--include-bssid can only be used with --create-baseline")
        if args.overwrite_baseline and args.create_baseline is None:
            parser.error("--overwrite-baseline can only be used with --create-baseline")
        if args.create_baseline is not None and not args.include_bssid:
            parser.error("--create-baseline requires at least one explicit --include-bssid")
        baseline = read_baseline(args.baseline) if args.baseline is not None else None
        if args.create_baseline is not None:
            if not args.create_baseline.parent.is_dir():
                raise ValueError("baseline output directory does not exist")
            if args.create_baseline.exists() and not args.overwrite_baseline:
                raise FileExistsError(f"baseline already exists: {args.create_baseline}")

        scan = windows_wlan.scan_live(args.interface, timeout_seconds=args.timeout)
        report = scan_to_dict(scan, baseline=baseline)
        baseline_created = None
        if args.create_baseline is not None:
            selected = build_baseline(scan.access_points, args.include_bssid)
            write_baseline(args.create_baseline, selected, overwrite=args.overwrite_baseline)
            baseline_created = len(selected.access_points)
        if args.json:
            if baseline_created is not None:
                report["baseline_created"] = {"entries": baseline_created}
            print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
        else:
            _print_scan(scan, report, baseline_created)
        return 0
    except (OSError, TypeError, ValueError, windows_wlan.WlanApiError) as exc:
        print(f"wifi-security-analyzer: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
