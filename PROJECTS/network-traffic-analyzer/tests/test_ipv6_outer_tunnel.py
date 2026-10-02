"""An IPv6-outer tunnel must not be reported as its inner transport.

The earlier tunnel guard assumed IPv4 was always the outer header, so a capture
whose outer header is IPv6 but that carries an IPv4 tunnel was reported as the
inner UDP/TCP with the inner addresses and DNS name.
"""
import pytest

pytest.importorskip("scapy")
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from src.analyzer import analyze_pcap


def test_ipv6_outer_tunnel_is_not_reported_as_its_inner_transport(tmp_path):
    capture = tmp_path / "ipv6-outer-tunnel.pcap"
    wrpcap(str(capture), [
        Ether()
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(dport=53)
        / DNS(qr=0, qd=DNSQR(qname="inner-never-sent.test")),
    ])
    report = analyze_pcap(capture)
    assert report["protocols"] == {"IPv6": 1}
    assert report["top_sources"] == {"2001:db8::1": 1}
    assert report["top_destinations"] == {"2001:db8::2": 1}
    assert report["destination_ports"] == {}
    assert report["dns_queries"] == {}
