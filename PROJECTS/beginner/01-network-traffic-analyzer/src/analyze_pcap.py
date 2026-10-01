"""Small PCAP traffic summary tool."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

@dataclass(frozen=True)
class TrafficRecord:
    """Packet fields used in the summary."""

    protocol: str
    source: str | None = None
    destination: str | None = None
    destination_port: int | None = None
    dns_query: str | None = None

def summarize_records(records: Iterable[TrafficRecord]) -> dict[str, Any]:
    """Count protocols, hosts, ports, and DNS names."""

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

def packet_to_record(packet: Any) -> TrafficRecord:
    """Pull the fields we need from one Scapy packet."""

    # Import Scapy here so the summary code can load without it.
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    source = destination = None

    # Use IPv4 first, then fall back to IPv6.
    if IP in packet:
        source, destination = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        source, destination = packet[IPv6].src, packet[IPv6].dst

    # Pick the transport protocol and destination port.
    protocol = "OTHER"
    destination_port = None
    if TCP in packet:
        protocol, destination_port = "TCP", int(packet[TCP].dport)
    elif UDP in packet:
        protocol, destination_port = "UDP", int(packet[UDP].dport)
    elif source:
        protocol = "IP"

    # Keep the DNS name when this packet contains a query.
    dns_query = None
    if DNS in packet and packet[DNS].qr == 0 and DNSQR in packet:
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

def analyse_pcap(path: Path) -> dict[str, Any]:
    """Read a PCAP and return its summary."""

    from scapy.all import rdpcap

    from scapy.error import Scapy_Exception

    try:
        packets = rdpcap(str(path))
    except (Scapy_Exception, OSError, EOFError) as exc:
        raise ValueError(f"Could not read capture {path}: {exc}") from exc
    return summarize_records(packet_to_record(packet) for packet in packets)

def print_summary(summary: dict[str, Any]) -> None:
    """Print the traffic summary."""

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

def main() -> None:
    """Read the command-line arguments and run the analyzer."""

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
    except (ValueError, OSError) as exc:
        raise SystemExit(str(exc)) from exc

if __name__ == "__main__":
    main()
