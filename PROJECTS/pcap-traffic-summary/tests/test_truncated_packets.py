"""Hardening checks for captures whose packets are cut short."""
import struct

import pytest

pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from src.analyze_pcap import analyse_pcap, packet_to_record, port_number


def write_raw_capture(path, frame):
    """Write a one-packet Ethernet capture so a cut frame can be tested exactly."""
    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    path.write_bytes(global_header + record)


def test_port_number_is_not_invented_for_a_missing_field():
    assert port_number(None) is None
    assert port_number("") is None
    assert port_number("443") == 443


def test_snaplen_truncated_packet_is_summarised_without_crashing(tmp_path):
    path = tmp_path / "truncated.pcap"
    ethernet = bytes.fromhex("001122334455" "66778899aabb" "0800")
    ipv4 = bytes.fromhex("4500" "003c" "0001" "0000" "40" "06" "0000" "c000020a" "c0000214")
    write_raw_capture(path, ethernet + ipv4 + b"\xc3\x50")
    summary = analyse_pcap(path)
    assert summary["packet_count"] == 1
    assert summary["source_hosts"] == {"192.0.2.10": 1}
    assert summary["destination_ports"] == {}


def test_a_local_capture_still_decodes(tmp_path):
    capture = tmp_path / "local.pcap"
    wrpcap(str(capture), [Ether()/IP(src="203.0.113.5", dst="203.0.113.9")/TCP(dport=8443, flags="S")])
    summary = analyse_pcap(capture)
    assert summary["protocols"] == {"TCP": 1}
    assert summary["destination_ports"] == {8443: 1}
