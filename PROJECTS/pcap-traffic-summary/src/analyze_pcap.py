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
    dns_queries: tuple[str, ...] = ()

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
        # Every question is reported; a packet can ask more than one name.
        "dns_queries": [
            name.rstrip(".")
            for record in records
            for name in (record.dns_queries or ((record.dns_query,) if record.dns_query else ()))
        ],
    }

def port_number(value: Any) -> int | None:
    """Return a usable port number, or None when a truncated packet omits it."""

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def packet_transport(packet: Any) -> Any:
    """Return the packet's own transport layer, or None.

    A capture can nest IP headers (a tunnel) or quote one inside an ICMP
    error. Those inner headers are payload rather than live traffic, so only
    the outer transport should decide the protocol, port, and DNS name.
    """

    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    network = packet[IP] if IP in packet else (packet[IPv6] if IPv6 in packet else None)
    layer = network.payload if network is not None else None
    while layer is not None:
        if isinstance(layer, (TCP, UDP)):
            return layer
        if isinstance(layer, (IP, IPv6)) or type(layer).__name__.startswith("ICMP"):
            return None
        next_layer = getattr(layer, "payload", None)
        if next_layer is None or next_layer is layer:
            return None
        layer = next_layer
    return None

def dns_question_names(dns_layer: Any) -> tuple[str, ...]:
    """Return every question name in a DNS query layer.

    Scapy exposes several questions either as a list of ``DNSQR`` entries or as
    a chain hanging off the first one, so both shapes are walked here.
    """

    from scapy.layers.dns import DNSQR

    entries = dns_layer.qd if isinstance(dns_layer.qd, list) else [dns_layer.qd]
    names: list[str] = []
    for entry in entries:
        while entry is not None:
            raw = getattr(entry, "qname", None)
            if raw is not None:
                text = (
                    raw.decode("utf-8", errors="replace")
                    if isinstance(raw, bytes)
                    else str(raw)
                )
                text = text.strip().rstrip(".")
                if text:
                    names.append(text)
            following = getattr(entry, "payload", None)
            entry = following if isinstance(following, DNSQR) else None
    return tuple(names)


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

    # Only the packet's own transport counts; a header quoted by an ICMP error
    # or carried inside a tunnel belongs to a different packet.
    transport = packet_transport(packet)

    # Pick the transport protocol and destination port.
    protocol = "OTHER"
    destination_port = None
    if isinstance(transport, TCP):
        protocol, destination_port = "TCP", port_number(transport.dport)
    elif isinstance(transport, UDP):
        protocol, destination_port = "UDP", port_number(transport.dport)
    elif source:
        protocol = "IPv6" if IPv6 in packet else "IP"

    # Keep the DNS names when the packet's own transport carries a query.
    questions: tuple[str, ...] = ()
    if transport is not None and DNS in transport and transport[DNS].qr == 0:
        questions = dns_question_names(transport[DNS])

    return TrafficRecord(
        protocol,
        source,
        destination,
        destination_port,
        questions[0] if questions else None,
        questions,
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
