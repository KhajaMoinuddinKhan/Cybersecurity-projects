"""Byte totals and byte-ranked rankings come from the captured frame sizes."""
from src.analyzer import PacketRecord, summarize


def test_total_bytes_and_bytes_per_protocol():
    report = summarize([
        PacketRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, source_port=50000, size=100),
        PacketRecord("TCP", "10.0.0.2", "10.0.0.1", 50000, None, source_port=443, size=50),
        PacketRecord("UDP", "10.0.0.1", "10.0.0.3", 53, "a.test", source_port=40000, size=70),
    ])
    assert report["total_bytes"] == 220
    assert report["bytes_per_protocol"] == {"TCP": 150, "UDP": 70}


def test_talkers_are_ranked_by_packets_and_by_bytes_separately():
    report = summarize([
        PacketRecord("TCP", "A", "B", 443, None, source_port=1, size=10),
        PacketRecord("TCP", "A", "B", 443, None, source_port=1, size=10),
        PacketRecord("TCP", "A", "B", 443, None, source_port=1, size=10),
        PacketRecord("UDP", "C", "B", 53, None, source_port=2, size=1000),
    ])
    by_packets = [row["host"] for row in report["top_talkers_by_packets"]]
    by_bytes = [row["host"] for row in report["top_talkers_by_bytes"]]
    assert by_packets == ["B", "A", "C"]      # B is an endpoint of every packet
    assert by_bytes == ["B", "C", "A"]        # C's one packet outweighs A's three
    assert report["top_talkers_by_bytes"][0] == {"host": "B", "packets": 4, "bytes": 1030}
    assert report["top_talkers_by_packets"][1] == {"host": "A", "packets": 3, "bytes": 30}
