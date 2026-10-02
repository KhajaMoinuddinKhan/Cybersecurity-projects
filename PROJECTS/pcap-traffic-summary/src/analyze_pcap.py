"""PCAP traffic summary tool."""
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


def outer_network_layer(packet: Any) -> Any:
    """Return the packet's own outermost IP or IPv6 layer, or None.

    Scapy's ``packet[IP]`` returns the first IPv4 layer wherever it sits, so a
    capture whose outer header is IPv6 but that carries an IPv4 tunnel would
    hand back the inner header. Walking the layers in order keeps the outermost
    one, which is the header that describes the packet on the wire.
    """

    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    layer = packet
    while layer is not None:
        if isinstance(layer, (IP, IPv6)):
            return layer
        following = getattr(layer, "payload", None)
        if following is layer:
            return None
        layer = following
    return None


def packet_transport(packet: Any) -> Any:
    """Return the packet's own transport layer, or None.

    A capture can nest IP headers (a tunnel) or quote one inside an ICMP
    error. Those inner headers are payload rather than live traffic, so only
    the outer transport should decide the protocol, port, and DNS name.
    """

    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    network = outer_network_layer(packet)
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
    from scapy.layers.dns import DNS
    from scapy.layers.inet import TCP, UDP

    source = destination = None

    # The packet's own (outermost) network layer gives the addresses. An inner
    # header quoted by an ICMP error or carried in a tunnel is payload, not the
    # packet's own addressing.
    network = outer_network_layer(packet)
    if network is not None:
        source, destination = network.src, network.dst

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
        # No transport of its own: IPv4 and IPv6 traffic are both counted as IP.
        protocol = "IP"

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

def printable(value: Any) -> str:
    """Render a captured name so it cannot drive the terminal.

    A host name or DNS question in a capture is attacker-controlled data. Printed
    raw, a name carrying escape or control characters could clear the screen or
    rewrite what the analyst sees. Anything unprintable is shown as an escape
    sequence instead, and the JSON report escapes the same characters itself.
    """

    text = str(value)
    return "".join(character if character.isprintable() else f"\\x{ord(character):02x}" for character in text)


def print_summary(summary: dict[str, Any]) -> None:
    """Print the traffic summary."""

    print(f"Packets analysed: {summary['packet_count']}")

    print("\nProtocols:")
    if not summary["protocols"]:
        print("  No observed values")
    for name, count in summary["protocols"].most_common():
        print(f"  {printable(name)}: {count}")

    print("\nTop source hosts:")
    if not summary["source_hosts"]:
        print("  No observed values")
    for host, count in summary["source_hosts"].most_common(10):
        print(f"  {printable(host)}: {count} packets")

    print("\nTop destination ports:")
    if not summary["destination_ports"]:
        print("  No observed values")
    for port, count in summary["destination_ports"].most_common(10):
        print(f"  {port}: {count} packets")

    if summary["dns_queries"]:
        print("\nDNS queries:")
        for query in summary["dns_queries"][:20]:
            print(f"  {printable(query)}")

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
