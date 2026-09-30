"""Summarise a PCAP for basic defensive network analysis."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


# [SECTION] Normalized packet model
# Scapy packets contain many protocol-specific fields. This small data class keeps
# only the fields the analyzer needs so the summarization logic stays easy to test.
@dataclass(frozen=True)
class TrafficRecord:
    """Represent the security-relevant fields extracted from one packet."""

    protocol: str
    source: str | None = None
    destination: str | None = None
    destination_port: int | None = None
    dns_query: str | None = None


# [SECTION] Traffic summarization
# This function works on TrafficRecord objects rather than raw Scapy packets. That
# separation lets tests exercise the counting logic without needing a PCAP file.
def summarize_records(records: Iterable[TrafficRecord]) -> dict[str, Any]:
    """Aggregate packet records into protocol, host, port, and DNS statistics."""

    records = list(records)
    return {
        "packet_count": len(records),
        "protocols": Counter(record.protocol.upper() for record in records),
        "source_hosts": Counter(record.source for record in records if record.source),
        "destination_ports": Counter(
            record.destination_port
            for record in records
            if record.destination_port is not None
        ),
        "dns_queries": [
            record.dns_query.rstrip(".")
            for record in records
            if record.dns_query
        ],
    }


# [SECTION] Packet parsing
# Scapy is imported inside the function so the pure summarization code can still
# be imported and tested on systems where Scapy is not installed.
def packet_to_record(packet: Any) -> TrafficRecord:
    """Convert a raw Scapy packet into a simplified TrafficRecord."""

    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    source = destination = None

    # Prefer IPv4 fields when present, otherwise fall back to IPv6.
    if IP in packet:
        source, destination = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        source, destination = packet[IPv6].src, packet[IPv6].dst

    # Identify the transport protocol and capture a destination port when one exists.
    protocol = "OTHER"
    destination_port = None
    if TCP in packet:
        protocol, destination_port = "TCP", int(packet[TCP].dport)
    elif UDP in packet:
        protocol, destination_port = "UDP", int(packet[UDP].dport)
    elif source:
        protocol = "IP"

    # DNS queries are useful during incident review because they show requested names.
    dns_query = None
    if DNS in packet and getattr(packet[DNS], "qdcount", 0) and DNSQR in packet:
        raw_query = packet[DNSQR].qname
        dns_query = (
            raw_query.decode("utf-8", errors="replace")
            if isinstance(raw_query, bytes)
            else str(raw_query)
        )

    return TrafficRecord(
        protocol,
        source,
        destination,
        destination_port,
        dns_query,
    )


# [SECTION] PCAP loading
def analyse_pcap(path: Path) -> dict[str, Any]:
    """Read a PCAP file with Scapy and return its summarized security data."""

    from scapy.all import rdpcap

    return summarize_records(packet_to_record(packet) for packet in rdpcap(str(path)))


# [SECTION] Console reporting
def print_summary(summary: dict[str, Any]) -> None:
    """Print a human-readable report from the aggregated traffic summary."""

    print(f"Packets analysed: {summary['packet_count']}")

    print("\nProtocols:")
    for name, count in summary["protocols"].most_common():
        print(f"  {name}: {count}")

    print("\nTop source hosts:")
    for host, count in summary["source_hosts"].most_common(10):
        print(f"  {host}: {count} packets")

    print("\nTop destination ports:")
    for port, count in summary["destination_ports"].most_common(10):
        print(f"  {port}: {count} packets")

    if summary["dns_queries"]:
        print("\nDNS queries:")
        for query in summary["dns_queries"][:20]:
            print(f"  {query}")


# [SECTION] Command-line interface
def main() -> None:
    """Parse CLI arguments, validate the PCAP path, and print the analysis."""

    parser = argparse.ArgumentParser(
        description="Summarise a PCAP for basic defensive network analysis."
    )
    parser.add_argument("pcap", type=Path)
    args = parser.parse_args()

    if not args.pcap.is_file():
        raise SystemExit(f"PCAP file not found: {args.pcap}")

    try:
        print_summary(analyse_pcap(args.pcap))
    except ImportError as exc:
        raise SystemExit(
            "Scapy is required. Run: python -m pip install -r requirements.txt"
        ) from exc


if __name__ == "__main__":
    main()
