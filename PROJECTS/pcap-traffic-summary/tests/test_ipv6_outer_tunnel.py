"""A tunnel's inner header must not decide the packet's own fields.

An IPv6 packet can carry an IPv4 tunnel. The earlier tunnel guard only caught
the case where IPv4 was the outer header, so an IPv6-outer tunnel was reported
as its inner UDP/TCP, with the inner addresses and DNS name.
"""
import pytest

pytest.importorskip("scapy")
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import wrpcap

from src.analyze_pcap import analyse_pcap, packet_to_record, print_summary, summarize_records


def test_ipv6_outer_tunnel_is_not_reported_as_its_inner_transport(tmp_path):
    capture = tmp_path / "ipv6-outer-tunnel.pcap"
    packet = (
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(dport=53)
        / DNS(qr=0, qd=DNSQR(qname="inner-never-sent.test"))
    )
    wrpcap(str(capture), [packet])
    result = analyse_pcap(capture)
    assert result["protocols"] == {"IP": 1}
    assert result["source_hosts"] == {"2001:db8::1": 1}
    assert result["destination_ports"] == {}
    assert result["dns_queries"] == []


def test_ipv6_packet_with_no_transport_is_counted_as_ip():
    record = packet_to_record(IPv6(src="2001:db8::1", dst="2001:db8::2"))
    assert record.protocol == "IP"
    assert record.source == "2001:db8::1"


def test_empty_summary_reports_no_observed_values(capsys):
    print_summary(summarize_records([]))
    out = capsys.readouterr().out
    # Every section that can be empty says so rather than showing a fabricated
    # row: the capture time, protocols, source hosts, destination ports and flows.
    assert out.count("No observed values") == 5
    for section in ("Capture time:", "Protocols:", "Top source hosts by bytes",
                    "Top destination ports", "Top flows by bytes"):
        assert section in out
