"""Byte, flow and time accounting, which the packet counts alone cannot show."""
import json
import subprocess
import sys

import pytest

pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from src.analyze_pcap import TrafficRecord, analyse_pcap, flow_key, summarize_records


def test_bytes_are_totalled_and_split_by_protocol():
    records = [
        TrafficRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, (), 5000, 1500),
        TrafficRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, (), 5001, 60),
        TrafficRecord("UDP", "10.0.0.1", "8.8.8.8", 53, "example.test.", (), 5002, 90),
    ]
    summary = summarize_records(records)
    assert summary["packet_count"] == 3
    assert summary["byte_count"] == 1650
    assert summary["protocol_bytes"]["TCP"] == 1560
    assert summary["protocol_bytes"]["UDP"] == 90


def test_hosts_are_ranked_by_bytes_not_only_by_packets():
    """One large packet should outrank several small ones."""
    records = [
        TrafficRecord("TCP", "10.0.0.9", "10.0.0.2", 443, None, (), 1, 1400),
        TrafficRecord("TCP", "10.0.0.1", "10.0.0.2", 80, None, (), 2, 60),
        TrafficRecord("TCP", "10.0.0.1", "10.0.0.2", 80, None, (), 3, 60),
    ]
    summary = summarize_records(records)
    assert summary["source_hosts"]["10.0.0.1"] == 2      # more packets
    assert summary["source_bytes"]["10.0.0.9"] == 1400   # more bytes
    assert summary["source_bytes"].most_common(1)[0][0] == "10.0.0.9"


def test_flows_group_by_the_full_five_tuple():
    records = [
        TrafficRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, (), 5000, 100),
        TrafficRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, (), 5000, 200),
        TrafficRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, (), 5001, 50),
    ]
    summary = summarize_records(records)
    assert summary["flows"]["10.0.0.1:5000 -> 10.0.0.2:443 TCP"] == 2
    assert summary["flow_bytes"]["10.0.0.1:5000 -> 10.0.0.2:443 TCP"] == 300
    assert summary["flows"]["10.0.0.1:5001 -> 10.0.0.2:443 TCP"] == 1


def test_flow_key_omits_a_port_it_does_not_have():
    assert flow_key(TrafficRecord("IP", "10.0.0.1", "10.0.0.2")) == "10.0.0.1 -> 10.0.0.2 IP"


def test_capture_time_range_and_duration():
    records = [
        TrafficRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, (), 1, 100, 1000.0),
        TrafficRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, (), 2, 100, 1002.5),
        TrafficRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, (), 3, 100, 1001.0),
    ]
    summary = summarize_records(records)
    assert summary["first_timestamp"] == 1000.0
    assert summary["last_timestamp"] == 1002.5
    assert summary["duration_seconds"] == 2.5


def test_no_timestamps_means_no_duration_rather_than_zero():
    summary = summarize_records([TrafficRecord("TCP", "10.0.0.1", "10.0.0.2", 443)])
    assert summary["first_timestamp"] is None
    assert summary["duration_seconds"] is None


def test_a_real_capture_is_summarised_with_bytes_and_flows(tmp_path):
    capture = tmp_path / "lab.pcap"
    packets = [
        Ether() / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=5000, dport=443),
        Ether() / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=5000, dport=443),
        Ether() / IP(src="192.0.2.10", dst="198.51.100.53") / UDP(sport=5100, dport=53),
    ]
    for offset, packet in enumerate(packets):
        packet.time = 2000.0 + offset
    wrpcap(str(capture), packets)

    summary = analyse_pcap(capture)
    assert summary["packet_count"] == 3
    assert summary["byte_count"] == sum(len(packet) for packet in packets)
    assert summary["flows"]["192.0.2.10:5000 -> 192.0.2.20:443 TCP"] == 2
    assert summary["duration_seconds"] == 2.0


def test_top_limits_each_ranking(capsys):
    records = [
        TrafficRecord("TCP", f"10.0.0.{index}", "10.0.0.99", 1000 + index, None, (), index, index)
        for index in range(1, 8)
    ]
    from src.analyze_pcap import print_summary

    print_summary(summarize_records(records), top=3)
    out = capsys.readouterr().out

    # Split on the section headers so each ranking is counted on its own; the
    # same phrasing appears in more than one section.
    sections = {}
    current = None
    for line in out.splitlines():
        if line.endswith(":") and not line.startswith("  "):
            current = line
            sections[current] = []
        elif current and line.startswith("  "):
            sections[current].append(line)

    assert len(sections["Top source hosts by bytes (top 3):"]) == 3
    assert len(sections["Top destination ports (top 3):"]) == 3
    assert len(sections["Top flows by bytes (top 3):"]) == 3


def test_json_report_is_serialisable_and_carries_the_new_fields(tmp_path):
    capture = tmp_path / "json.pcap"
    wrpcap(str(capture), [Ether() / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=5000, dport=443)])
    result = subprocess.run(
        [sys.executable, "-m", "src.analyze_pcap", str(capture), "--json"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["byte_count"] > 0
    assert report["flows"] == {"192.0.2.10:5000 -> 192.0.2.20:443 TCP": 1}
    assert "duration_seconds" in report


def test_top_rejects_a_value_below_one(tmp_path):
    capture = tmp_path / "top.pcap"
    wrpcap(str(capture), [Ether() / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(dport=443)])
    result = subprocess.run(
        [sys.executable, "-m", "src.analyze_pcap", str(capture), "--top", "0"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode != 0
    assert "at least 1" in result.stderr
