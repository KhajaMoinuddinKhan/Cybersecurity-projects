import pytest
try:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, UDP
    from scapy.utils import wrpcap
except PermissionError:
    pytest.skip("Scapy interface discovery is blocked in this restricted environment", allow_module_level=True)
from src.analyze_pcap import analyse_pcap


def test_dns_responses_do_not_count_as_queries(tmp_path):
    capture = tmp_path / "dns.pcap"
    query = IP(src="192.0.2.1", dst="192.0.2.2") / UDP(dport=53) / DNS(qr=0, qd=DNSQR(qname="example.test"))
    reply = IP(src="192.0.2.2", dst="192.0.2.1") / UDP(sport=53) / DNS(qr=1, qd=DNSQR(qname="example.test"))
    wrpcap(str(capture), [query, reply])
    result = analyse_pcap(capture)
    assert result["packet_count"] == 2
    assert result["dns_queries"] == ["example.test"]
