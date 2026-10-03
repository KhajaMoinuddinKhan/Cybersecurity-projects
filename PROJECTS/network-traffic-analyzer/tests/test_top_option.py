"""--top caps every ranking without changing the totals."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from src.analyzer import PacketRecord, summarize


def _records():
    records = []
    for index in range(6):
        host = f"10.0.0.{index}"
        for _ in range(index + 1):
            records.append(PacketRecord("TCP", host, "10.0.1.1", 443, None, source_port=1000 + index, size=10))
    return records


def test_top_limits_every_ranking():
    report = summarize(_records(), top=2)
    assert report["packet_count"] == 21           # the totals still cover the whole capture
    assert len(report["protocols"]) == 1
    assert len(report["top_sources"]) == 2
    assert len(report["top_destinations"]) == 1
    assert len(report["top_talkers_by_packets"]) == 2
    assert len(report["top_talkers_by_bytes"]) == 2
    assert len(report["top_flows"]) == 2


def test_top_one_keeps_only_the_busiest_entry():
    report = summarize(_records(), top=1)
    assert list(report["top_sources"]) == ["10.0.0.5"]          # busiest sender
    assert report["top_talkers_by_packets"][0]["host"] == "10.0.1.1"  # endpoint of every packet
    assert report["top_talkers_by_packets"][0]["packets"] == 21


def test_cli_top_option_caps_a_real_capture(tmp_path):
    capture = tmp_path / "top.pcap"
    wrpcap(str(capture), [
        Ether()/IP(src=f"192.0.2.{index}", dst="192.0.2.1")/TCP(sport=1000 + index, dport=443, flags="S")
        for index in range(4)
    ])
    project = Path(__file__).resolve().parents[1]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(project)
    result = subprocess.run(
        [sys.executable, "-m", "src.analyzer", str(capture), "--json", "--top", "2"],
        cwd=str(project), capture_output=True, text=True, env=environment, timeout=180,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["packet_count"] == 4
    assert len(report["top_sources"]) == 2
    assert len(report["top_flows"]) == 2
