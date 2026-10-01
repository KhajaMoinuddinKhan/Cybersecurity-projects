"""A header quoted inside an ICMP error is payload, not live traffic."""
import pytest

pytest.importorskip("scapy")
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from src.analyze_pcap import analyse_pcap, packet_to_record


def test_dns_query_quoted_in_icmp_error_is_not_reported(tmp_path):
    capture = tmp_path / "icmp-quoted.pcap"
    quoted = (
        Ether()
        / IP(src="192.0.2.9", dst="192.0.2.5")
        / ICMP(type=3, code=1)
        / IP(src="192.0.2.5", dst="198.51.100.53")
        / UDP(dport=53)
        / DNS(qr=0, qd=DNSQR(qname="quoted-never-sent.test"))
    )
    wrpcap(str(capture), [quoted])
    result = analyse_pcap(capture)
    assert result["packet_count"] == 1
    assert result["dns_queries"] == []


def test_in_memory_icmp_error_is_not_labelled_as_transport_traffic():
    packet = (
        IP(src="192.0.2.9", dst="192.0.2.5")
        / ICMP(type=3, code=3)
        / IP(src="192.0.2.5", dst="192.0.2.9")
        / UDP(dport=53)
        / DNS(qr=0, qd=DNSQR(qname="phantom.test"))
    )
    record = packet_to_record(packet)
    assert record.dns_query is None
    assert record.protocol == "IP"
    assert record.destination_port is None
