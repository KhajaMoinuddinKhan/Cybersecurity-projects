"""Only the packet's own outer transport describes the traffic."""
import pytest

pytest.importorskip("scapy")
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from src.analyzer import PacketRecord, analyze_pcap, summarize


def test_header_quoted_by_an_icmp_error_is_not_live_traffic(tmp_path):
    capture = tmp_path / "quoted.pcap"
    quoted = (
        IP(src="198.51.100.9", dst="198.51.100.53")
        / UDP(sport=40000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="quoted-never-sent.test"))
    )
    wrpcap(str(capture), [Ether()/IP(src="198.51.100.1", dst="192.0.2.10")/ICMP(type=3, code=3)/quoted])
    report = analyze_pcap(capture)
    assert report["packet_count"] == 1
    assert report["protocols"] == {"IP": 1}
    assert report["destination_ports"] == {}
    assert report["dns_queries"] == {}


def test_tunnelled_packet_is_reported_as_ip_not_as_its_inner_transport(tmp_path):
    capture = tmp_path / "tunnel.pcap"
    wrpcap(str(capture), [
        Ether()/IP(src="10.0.0.1", dst="10.0.0.2")
        / IP(src="172.16.0.1", dst="172.16.0.2") / UDP(dport=1234) / b"x",
    ])
    report = analyze_pcap(capture)
    assert report["protocols"] == {"IP": 1}
    assert report["destination_ports"] == {}


def test_every_question_in_one_packet_is_counted(tmp_path):
    capture = tmp_path / "two-questions.pcap"
    wrpcap(str(capture), [
        Ether()/IP(src="192.0.2.1", dst="192.0.2.53")/UDP(dport=53)
        / DNS(qr=0, qd=[DNSQR(qname="first.test"), DNSQR(qname="second.test")]),
    ])
    report = analyze_pcap(capture)
    assert report["dns_queries"] == {"first.test": 1, "second.test": 1}


def test_a_real_flow_is_still_reported():
    report = summarize([PacketRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None)])
    assert report["protocols"] == {"TCP": 1}
    assert report["destination_ports"] == {"443": 1}
