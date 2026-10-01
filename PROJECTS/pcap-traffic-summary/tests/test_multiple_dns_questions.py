"""A single DNS packet can ask more than one question."""
import pytest

pytest.importorskip("scapy")
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.utils import wrpcap

from src.analyze_pcap import TrafficRecord, analyse_pcap, summarize_records


def test_every_question_in_one_packet_is_reported(tmp_path):
    capture = tmp_path / "two-questions.pcap"
    packet = (
        IP(src="192.0.2.1", dst="192.0.2.2")
        / UDP(dport=53)
        / DNS(qr=0, qd=[DNSQR(qname="first.test"), DNSQR(qname="second.test")])
    )
    wrpcap(str(capture), [packet])
    result = analyse_pcap(capture)
    assert result["packet_count"] == 1
    assert result["dns_queries"] == ["first.test", "second.test"]


def test_summary_counts_every_name_on_one_record():
    record = TrafficRecord(
        "UDP", "10.0.0.1", "10.0.0.2", 53, "first.test", ("first.test", "second.test")
    )
    assert summarize_records([record])["dns_queries"] == ["first.test", "second.test"]


def test_single_question_still_reads_the_old_field():
    assert summarize_records([TrafficRecord("UDP", "10.0.0.1", "10.0.0.2", 53, "one.test.")])[
        "dns_queries"
    ] == ["one.test"]
