"""The --host, --port and --protocol options restrict the report."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("scapy")
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from src.analyzer import Filters, PacketRecord, summarize


RECORDS = [
    PacketRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, source_port=50000, size=100, timestamp=1.0),
    PacketRecord("UDP", "10.0.0.1", "10.0.0.3", 53, "example.test", source_port=40000, size=70, timestamp=2.0),
    PacketRecord("TCP", "10.0.0.2", "10.0.0.1", 80, None, source_port=33000, size=40, timestamp=3.0),
]


def test_host_filter_matches_either_endpoint():
    report = summarize(RECORDS, filters=Filters(host="10.0.0.2"))
    assert report["packet_count"] == 2
    assert report["packets_read"] == 3
    assert report["filters"] == {"host": "10.0.0.2", "port": None, "protocol": None}


def test_port_filter_matches_source_or_destination():
    report = summarize(RECORDS, filters=Filters(port=53))
    assert report["packet_count"] == 1
    assert report["dns_queries"] == {"example.test": 1}


def test_protocol_filter_is_case_insensitive():
    report = summarize(RECORDS, filters=Filters(protocol="udp"))
    assert report["packet_count"] == 1
    assert report["protocols"] == {"UDP": 1}


def test_filters_combine_with_and():
    report = summarize(RECORDS, filters=Filters(host="10.0.0.1", protocol="TCP"))
    assert report["packet_count"] == 2


def _run_cli(capture, project, *args):
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(project)
    return subprocess.run(
        [sys.executable, "-m", "src.analyzer", str(capture), *args],
        cwd=str(project), capture_output=True, text=True, env=environment, timeout=180,
    )


def test_cli_host_filter_restricts_a_real_capture(tmp_path):
    capture = tmp_path / "filters.pcap"
    wrpcap(str(capture), [
        Ether()/IP(src="192.0.2.10", dst="192.0.2.53")/UDP(sport=40000, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.test")),
        Ether()/IP(src="192.0.2.10", dst="192.0.2.20")/TCP(sport=50000, dport=443, flags="S"),
        Ether()/IP(src="192.0.2.20", dst="192.0.2.10")/TCP(sport=443, dport=50000, flags="SA"),
    ])
    project = Path(__file__).resolve().parents[1]
    result = _run_cli(capture, project, "--json", "--host", "192.0.2.20")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["packet_count"] == 2
    assert report["packets_read"] == 3
    assert report["top_sources"] == {"192.0.2.10": 1, "192.0.2.20": 1}


def test_cli_port_filter_restricts_a_real_capture(tmp_path):
    capture = tmp_path / "port-filter.pcap"
    wrpcap(str(capture), [
        Ether()/IP(src="192.0.2.10", dst="192.0.2.53")/UDP(sport=40000, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.test")),
        Ether()/IP(src="192.0.2.10", dst="192.0.2.20")/TCP(sport=50000, dport=443, flags="S"),
    ])
    project = Path(__file__).resolve().parents[1]
    result = _run_cli(capture, project, "--json", "--port", "53")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["packet_count"] == 1
    assert report["destination_ports"] == {"53": 1}
