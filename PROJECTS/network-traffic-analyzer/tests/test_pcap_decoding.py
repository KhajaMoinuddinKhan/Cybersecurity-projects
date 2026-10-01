"""End-to-end checks: a real capture file must be decoded, not read as raw bytes."""
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("scapy")
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from src.analyzer import analyze_pcap


def test_ethernet_capture_is_decoded(tmp_path):
    capture = tmp_path / "lab.pcap"
    wrpcap(str(capture), [
        Ether()/IP(src="192.0.2.10", dst="192.0.2.53")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.test")),
        Ether()/IP(src="192.0.2.10", dst="192.0.2.20")/TCP(dport=443, flags="S"),
        Ether()/IP(src="192.0.2.10", dst="192.0.2.20")/TCP(dport=80, flags="S"),
    ])
    report = analyze_pcap(capture)
    assert report["packet_count"] == 3
    assert report["protocols"] == {"UDP": 1, "TCP": 2}
    assert report["top_sources"] == {"192.0.2.10": 3}
    assert report["top_destinations"] == {"192.0.2.53": 1, "192.0.2.20": 2}
    assert report["destination_ports"] == {"53": 1, "443": 1, "80": 1}
    assert report["dns_queries"] == {"example.test": 1}


def write_raw_capture(path, frame):
    """Write a one-packet Ethernet capture so a cut frame can be tested exactly."""
    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    path.write_bytes(global_header + record)


def test_snaplen_truncated_packet_is_reported_without_crashing(tmp_path):
    path = tmp_path / "truncated.pcap"
    ethernet = bytes.fromhex("001122334455" "66778899aabb" "0800")
    ipv4 = bytes.fromhex("4500" "003c" "0001" "0000" "40" "06" "0000" "c000020a" "c0000214")
    write_raw_capture(path, ethernet + ipv4 + b"\xc3\x50")  # transport header cut short
    report = analyze_pcap(path)
    assert report["packet_count"] == 1
    assert report["protocols"] == {"IP": 1}          # decoded as far as the capture goes
    assert report["top_sources"] == {"192.0.2.10": 1}
    assert report["destination_ports"] == {}          # a missing port is not invented


def test_missing_port_field_is_not_turned_into_a_port():
    from src.analyzer import port_number

    assert port_number(None) is None
    assert port_number("") is None
    assert port_number("443") == 443


def test_cli_decodes_a_capture_in_a_fresh_interpreter(tmp_path):
    """Run the documented command in a new interpreter, as a user would.

    Scapy maps a capture's link type only after the matching layer module is
    imported, so a reader created too early silently degrades to Raw packets.
    Only a fresh interpreter catches that ordering bug.
    """
    project = Path(__file__).resolve().parents[1]
    capture = tmp_path / "cli-lab.pcap"
    wrpcap(str(capture), [
        Ether()/IP(src="198.51.100.7", dst="198.51.100.53")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="cli.example")),
        Ether()/IP(src="198.51.100.7", dst="198.51.100.9")/TCP(dport=8443, flags="S"),
    ])
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(project)
    result = subprocess.run(
        [sys.executable, "-m", "src.analyzer", str(capture), "--json"],
        cwd=str(project), capture_output=True, text=True, env=environment, timeout=180,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["packet_count"] == 2
    assert report["protocols"] == {"UDP": 1, "TCP": 1}
    assert report["top_sources"] == {"198.51.100.7": 2}
    assert report["destination_ports"] == {"53": 1, "8443": 1}
    assert report["dns_queries"] == {"cli.example": 1}
