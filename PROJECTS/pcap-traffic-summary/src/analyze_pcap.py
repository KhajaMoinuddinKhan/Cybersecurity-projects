"""PCAP traffic summary tool."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
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
    source_port: int | None = None
    length: int = 0
    timestamp: float | None = None

def flow_key(record: TrafficRecord) -> str:
    """Return the record's unidirectional five-tuple as a readable string."""

    source = f"{record.source}:{record.source_port}" if record.source_port is not None else str(record.source)
    destination = (
        f"{record.destination}:{record.destination_port}"
        if record.destination_port is not None
        else str(record.destination)
    )
    return f"{source} -> {destination} {record.protocol.upper()}"

def summarize_records(records: Iterable[TrafficRecord]) -> dict[str, Any]:
    """Count protocols, hosts, ports, flows, bytes, and DNS names."""

    records = list(records)

    protocols: Counter[str] = Counter()
    protocol_bytes: Counter[str] = Counter()
    source_hosts: Counter[str] = Counter()
    source_bytes: Counter[str] = Counter()
    destination_ports: Counter[int] = Counter()
    port_bytes: Counter[int] = Counter()
    flows: Counter[str] = Counter()
    flow_bytes: Counter[str] = Counter()
    dns_queries: list[str] = []

    total_bytes = 0
    first: float | None = None
    last: float | None = None

    for record in records:
        protocol = record.protocol.upper()
        size = record.length or 0
        total_bytes += size

        protocols[protocol] += 1
        protocol_bytes[protocol] += size

        if record.source:
            source_hosts[record.source] += 1
            source_bytes[record.source] += size
        if record.destination_port is not None:
            destination_ports[record.destination_port] += 1
            port_bytes[record.destination_port] += size

        if record.source or record.destination:
            key = flow_key(record)
            flows[key] += 1
            flow_bytes[key] += size

        # Every question is reported; a packet can ask more than one name.
        for name in (record.dns_queries or ((record.dns_query,) if record.dns_query else ())):
            dns_queries.append(name.rstrip("."))

        if record.timestamp is not None:
            first = record.timestamp if first is None else min(first, record.timestamp)
            last = record.timestamp if last is None else max(last, record.timestamp)

    duration = None if first is None or last is None else max(0.0, last - first)

    return {
        "packet_count": len(records),
        "byte_count": total_bytes,
        "protocols": protocols,
        "protocol_bytes": protocol_bytes,
        "source_hosts": source_hosts,
        "source_bytes": source_bytes,
        "destination_ports": destination_ports,
        "destination_port_bytes": port_bytes,
        "flows": flows,
        "flow_bytes": flow_bytes,
        "dns_queries": dns_queries,
        "first_timestamp": first,
        "last_timestamp": last,
        "duration_seconds": duration,
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

    # Pick the transport protocol, source port, and destination port.
    protocol = "OTHER"
    destination_port = None
    source_port = None
    if isinstance(transport, TCP):
        protocol = "TCP"
        destination_port, source_port = port_number(transport.dport), port_number(transport.sport)
    elif isinstance(transport, UDP):
        protocol = "UDP"
        destination_port, source_port = port_number(transport.dport), port_number(transport.sport)
    elif source:
        # No transport of its own: IPv4 and IPv6 traffic are both counted as IP.
        protocol = "IP"

    # Keep the DNS names when the packet's own transport carries a query.
    questions: tuple[str, ...] = ()
    if transport is not None and DNS in transport and transport[DNS].qr == 0:
        questions = dns_question_names(transport[DNS])

    # The frame length on the wire, and when it was seen. A packet read back
    # from a file carries the capture timestamp; an in-memory packet may not.
    try:
        length = len(packet)
    except TypeError:
        length = 0
    timestamp = getattr(packet, "time", None)

    return TrafficRecord(
        protocol,
        source,
        destination,
        destination_port,
        questions[0] if questions else None,
        questions,
        source_port,
        length,
        float(timestamp) if timestamp is not None else None,
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


def plural(count: int, noun: str) -> str:
    """Render a count with its noun, using the singular when there is one."""

    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def format_timestamp(value: float | None) -> str:
    """Render a capture timestamp in UTC, or a dash when there is none."""

    if value is None:
        return "not recorded"
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def as_json_report(summary: dict[str, Any], top: int) -> dict[str, Any]:
    """Convert the counters into a plain, serialisable report."""

    duration = summary["duration_seconds"]
    return {
        "packet_count": summary["packet_count"],
        "byte_count": summary["byte_count"],
        "protocols": dict(summary["protocols"].most_common()),
        "protocol_bytes": dict(summary["protocol_bytes"].most_common()),
        "source_hosts": dict(summary["source_hosts"].most_common(top)),
        "source_bytes": dict(summary["source_bytes"].most_common(top)),
        "destination_ports": {str(k): v for k, v in summary["destination_ports"].most_common(top)},
        "destination_port_bytes": {str(k): v for k, v in summary["destination_port_bytes"].most_common(top)},
        "flows": dict(summary["flows"].most_common(top)),
        "flow_bytes": dict(summary["flow_bytes"].most_common(top)),
        "dns_queries": summary["dns_queries"][:20],
        "first_timestamp": summary["first_timestamp"],
        "last_timestamp": summary["last_timestamp"],
        "duration_seconds": duration,
        "packets_per_second": (
            None if not duration else round(summary["packet_count"] / duration, 3)
        ),
        "bytes_per_second": (
            None if not duration else round(summary["byte_count"] / duration, 3)
        ),
    }

def print_summary(summary: dict[str, Any], top: int = 10) -> None:
    """Print the traffic summary."""

    print(f"Packets analysed: {summary['packet_count']}")
    print(f"Bytes analysed: {summary['byte_count']}")

    print("\nCapture time:")
    duration = summary["duration_seconds"]
    if summary["first_timestamp"] is None:
        print("  No observed values")
    else:
        print(f"  first:    {format_timestamp(summary['first_timestamp'])}")
        print(f"  last:     {format_timestamp(summary['last_timestamp'])}")
        if duration:
            print(
                f"  duration: {duration:.3f}s"
                f" ({summary['packet_count'] / duration:.1f} packets/s,"
                f" {summary['byte_count'] / duration:.0f} bytes/s)"
            )
        else:
            print("  duration: under one timestamp, so no rate is reported")

    print("\nProtocols:")
    if not summary["protocols"]:
        print("  No observed values")
    for name, count in summary["protocols"].most_common():
        size = summary["protocol_bytes"][name]
        print(f"  {printable(name)}: {plural(count, 'packet')}, {plural(size, 'byte')}")

    print(f"\nTop source hosts by bytes (top {top}):")
    if not summary["source_bytes"]:
        print("  No observed values")
    for host, size in summary["source_bytes"].most_common(top):
        print(f"  {printable(host)}: {plural(size, 'byte')} in {plural(summary['source_hosts'][host], 'packet')}")

    print(f"\nTop destination ports (top {top}):")
    if not summary["destination_ports"]:
        print("  No observed values")
    for port, count in summary["destination_ports"].most_common(top):
        print(f"  {port}: {plural(count, 'packet')}, {plural(summary['destination_port_bytes'][port], 'byte')}")

    print(f"\nTop flows by bytes (top {top}):")
    if not summary["flow_bytes"]:
        print("  No observed values")
    for key, size in summary["flow_bytes"].most_common(top):
        print(f"  {printable(key)}: {plural(size, 'byte')} in {plural(summary['flows'][key], 'packet')}")

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
    parser.add_argument(
        "--json", action="store_true", help="Print the summary as JSON instead of a report"
    )
    parser.add_argument(
        "--top", type=int, default=10, help="How many entries each ranking shows"
    )
    args = parser.parse_args()

    if not args.pcap.is_file():
        raise SystemExit(f"PCAP file not found: {args.pcap}")
    if args.top < 1:
        raise SystemExit("--top must be at least 1")

    try:
        summary = analyse_pcap(args.pcap)
    except ImportError as exc:
        raise SystemExit(
            "Scapy is required. Run: python -m pip install -r requirements.txt"
        ) from exc
    except (ValueError, OSError) as exc:
        raise SystemExit(str(exc)) from exc

    if args.json:
        print(json.dumps(as_json_report(summary, args.top), indent=2, default=str))
        return
    print_summary(summary, args.top)

if __name__ == "__main__":
    main()
