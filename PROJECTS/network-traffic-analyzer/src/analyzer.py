"""Stream a PCAP into a compact, input-driven network report."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class PacketRecord:
    protocol: str
    source: str | None
    destination: str | None
    destination_port: int | None
    dns_query: str | None
    dns_queries: tuple[str, ...] = ()
    source_port: int | None = None
    size: int = 0
    timestamp: float | None = None


@dataclass(frozen=True)
class Filters:
    """Restrict a report to the packets that match every supplied field."""

    host: str | None = None
    port: int | None = None
    protocol: str | None = None

    @property
    def active(self) -> bool:
        return self.host is not None or self.port is not None or self.protocol is not None


@dataclass
class FlowState:
    """Running totals for one 5-tuple conversation."""

    packets: int = 0
    bytes: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None


def record_matches(record: PacketRecord, filters: Filters) -> bool:
    """Return True when a record survives every active filter.

    A host filter matches either endpoint, a port filter either transport port,
    and a protocol filter is compared case-insensitively.
    """
    if filters.host is not None and record.source != filters.host and record.destination != filters.host:
        return False
    if filters.port is not None and record.source_port != filters.port and record.destination_port != filters.port:
        return False
    if filters.protocol is not None and record.protocol.lower() != filters.protocol.lower():
        return False
    return True


def flow_key(record: PacketRecord) -> tuple[str, int | None, str, int | None, str]:
    """Return the 5-tuple that identifies a conversation."""
    return (record.source or "", record.source_port, record.destination or "", record.destination_port, record.protocol)


def flow_entry(key: tuple[str, int | None, str, int | None, str], state: FlowState) -> dict[str, Any]:
    """Turn one accumulated flow into a report entry."""
    first, last = state.first_timestamp, state.last_timestamp
    duration = round(last - first, 6) if first is not None and last is not None else None
    return {
        "source": key[0],
        "source_port": key[1],
        "destination": key[2],
        "destination_port": key[3],
        "protocol": key[4],
        "packets": state.packets,
        "bytes": state.bytes,
        "first_timestamp": first,
        "last_timestamp": last,
        "duration_seconds": duration,
    }


def summarize(records: Iterable[PacketRecord], *, top: int = 10, filters: Filters | None = None) -> dict[str, Any]:
    """Aggregate packet records without retaining the complete capture.

    Memory is tied to the number of distinct values seen (addresses, ports,
    names, flows), never to the number of packets read. ``top`` caps how many
    entries each ranking returns; ``filters`` drops non-matching packets before
    they are counted, while ``packets_read`` still records how many were seen.
    """
    filters = filters or Filters()
    packets = packets_read = total_bytes = 0
    protocols: Counter[str] = Counter()
    protocol_bytes: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    ports: Counter[int] = Counter()
    dns_queries: Counter[str] = Counter()
    talker_packets: Counter[str] = Counter()
    talker_bytes: Counter[str] = Counter()
    flows: dict[tuple[str, int | None, str, int | None, str], FlowState] = {}
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    for record in records:
        packets_read += 1
        if not record_matches(record, filters):
            continue
        packets += 1
        size = record.size
        total_bytes += size
        protocols[record.protocol] += 1
        protocol_bytes[record.protocol] += size
        if record.source:
            sources[record.source] += 1
            talker_packets[record.source] += 1
            talker_bytes[record.source] += size
        if record.destination:
            destinations[record.destination] += 1
            talker_packets[record.destination] += 1
            talker_bytes[record.destination] += size
        if record.destination_port is not None:
            ports[record.destination_port] += 1
        # Every question counts; one packet can ask more than one name.
        for name in (record.dns_queries or ((record.dns_query,) if record.dns_query else ())):
            dns_queries[name.rstrip(".")] += 1
        if record.timestamp is not None:
            if first_timestamp is None or record.timestamp < first_timestamp:
                first_timestamp = record.timestamp
            if last_timestamp is None or record.timestamp > last_timestamp:
                last_timestamp = record.timestamp
        if record.source and record.destination:
            key = flow_key(record)
            state = flows.get(key)
            if state is None:
                state = FlowState()
                flows[key] = state
            state.packets += 1
            state.bytes += size
            if record.timestamp is not None:
                if state.first_timestamp is None or record.timestamp < state.first_timestamp:
                    state.first_timestamp = record.timestamp
                if state.last_timestamp is None or record.timestamp > state.last_timestamp:
                    state.last_timestamp = record.timestamp

    duration = round(last_timestamp - first_timestamp, 6) if first_timestamp is not None and last_timestamp is not None else None
    packets_per_second = round(packets / duration, 6) if duration else None
    bytes_per_second = round(total_bytes / duration, 6) if duration else None

    def talker_row(host: str) -> dict[str, Any]:
        return {"host": host, "packets": talker_packets[host], "bytes": talker_bytes[host]}

    talkers_by_packets = [
        talker_row(host)
        for host, _ in sorted(talker_packets.items(), key=lambda item: (-item[1], -talker_bytes[item[0]], item[0]))[:top]
    ]
    talkers_by_bytes = [
        talker_row(host)
        for host, _ in sorted(talker_bytes.items(), key=lambda item: (-item[1], -talker_packets[item[0]], item[0]))[:top]
    ]
    top_flows = [
        flow_entry(key, state)
        for key, state in sorted(flows.items(), key=lambda item: (-item[1].bytes, -item[1].packets, str(item[0])))[:top]
    ]

    return {
        "packet_count": packets,
        "packets_read": packets_read,
        "total_bytes": total_bytes,
        "first_timestamp": first_timestamp,
        "last_timestamp": last_timestamp,
        "duration_seconds": duration,
        "average_packets_per_second": packets_per_second,
        "average_bytes_per_second": bytes_per_second,
        "protocols": dict(protocols.most_common(top)),
        "bytes_per_protocol": dict(protocol_bytes.most_common(top)),
        "top_sources": dict(sources.most_common(top)),
        "top_destinations": dict(destinations.most_common(top)),
        "destination_ports": {str(k): v for k, v in ports.most_common(top)},
        "dns_queries": dict(dns_queries.most_common(top)),
        "top_talkers_by_packets": talkers_by_packets,
        "top_talkers_by_bytes": talkers_by_bytes,
        "top_flows": top_flows,
        "filters": {"host": filters.host, "port": filters.port, "protocol": filters.protocol},
    }


def port_number(value: Any) -> int | None:
    """Return a usable port number, or None when a truncated packet omits it."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def load_scapy_layers() -> None:
    """Import the Scapy layers that register capture link types.

    Scapy learns how to map a capture's link type (DLT 1 to ``Ether``, for
    example) only when the matching layer module is imported. A reader created
    before that falls back to ``Raw`` packets, which silently reports every
    packet as OTHER with no addresses, ports, or DNS names.
    """
    from scapy.layers.dns import DNS, DNSQR  # noqa: F401  (registration side effect)
    from scapy.layers.inet import IP, TCP, UDP  # noqa: F401
    from scapy.layers.inet6 import IPv6  # noqa: F401


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

    A capture can nest IP headers (a tunnel) or quote one inside an ICMP error.
    Those inner headers are payload rather than live traffic, so only the outer
    transport should decide the protocol, port and DNS names.
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
        following = getattr(layer, "payload", None)
        if following is None or following is layer:
            return None
        layer = following
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
                text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                text = text.strip().rstrip(".")
                if text:
                    names.append(text)
            following = getattr(entry, "payload", None)
            entry = following if isinstance(following, DNSQR) else None
    return tuple(names)


def packet_record(packet: Any) -> PacketRecord:
    """Extract the fields used by the report from one Scapy packet."""
    from scapy.layers.dns import DNS
    from scapy.layers.inet import TCP, UDP
    from scapy.layers.inet6 import IPv6

    # The packet's own (outermost) network layer gives the addresses; an inner
    # header quoted by an ICMP error or carried in a tunnel is payload.
    network = outer_network_layer(packet)
    source = destination = None
    if network is not None:
        source, destination = network.src, network.dst

    # Only the packet's own transport counts; a header quoted by an ICMP error
    # or carried inside a tunnel belongs to a different packet.
    transport = packet_transport(packet)

    protocol, port, source_port = "OTHER", None, None
    if isinstance(transport, TCP):
        protocol, port = "TCP", port_number(transport.dport)
        source_port = port_number(transport.sport)
    elif isinstance(transport, UDP):
        protocol, port = "UDP", port_number(transport.dport)
        source_port = port_number(transport.sport)
    elif source:
        protocol = "IPv6" if isinstance(network, IPv6) else "IP"

    questions: tuple[str, ...] = ()
    if transport is not None and DNS in transport and transport[DNS].qr == 0:
        questions = dns_question_names(transport[DNS])

    # Bytes are the captured frame length Scapy reports, and the timestamp is
    # the capture clock; both come straight from the file.
    timestamp = getattr(packet, "time", None)
    return PacketRecord(
        protocol,
        source,
        destination,
        port,
        questions[0] if questions else None,
        questions,
        source_port,
        len(packet),
        float(timestamp) if timestamp is not None else None,
    )


def analyze_pcap(path: Path, *, top: int = 10, filters: Filters | None = None) -> dict[str, Any]:
    """Read a PCAP incrementally and return its observed report."""
    try:
        from scapy.error import Scapy_Exception
        load_scapy_layers()  # must run before the reader is created
        from scapy.utils import PcapReader
        with PcapReader(str(path)) as reader:
            return summarize((packet_record(packet) for packet in reader), top=top, filters=filters)
    except ImportError as exc:
        raise RuntimeError("Reading a capture needs Scapy") from exc
    except (OSError, ValueError, Scapy_Exception) as exc:
        raise ValueError(f"Could not read PCAP {path}: {exc}") from exc


def plural(count: int, noun: str) -> str:
    """Render a count with its noun, using the singular when there is one."""

    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def printable(value: Any) -> str:
    """Render a captured name so it cannot drive the terminal.

    Host names and DNS questions come from the capture, so they are attacker
    controlled. Printed raw, a name carrying control or escape characters could
    rewrite what the analyst sees; unprintable characters are shown escaped
    instead. The --json report escapes the same characters itself.
    """

    text = str(value)
    return "".join(character if character.isprintable() else f"\\x{ord(character):02x}" for character in text)


def format_timestamp(value: float | None) -> str:
    """Render an epoch timestamp as UTC, or say that none was seen."""
    if value is None:
        return "n/a"
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def format_seconds(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f} s"


def format_flow(flow: dict[str, Any]) -> str:
    """Render one flow as ``src:sport -> dst:dport proto`` plus its totals."""
    source_port = flow["source_port"] if flow["source_port"] is not None else "-"
    destination_port = flow["destination_port"] if flow["destination_port"] is not None else "-"
    return (
        f"{printable(flow['source'])}:{source_port} -> {printable(flow['destination'])}:{destination_port} "
        f"{printable(flow['protocol'])}: {plural(flow['packets'], 'packet')}, {plural(flow['bytes'], 'byte')}, "
        f"{format_seconds(flow['duration_seconds'])}"
    )


def print_report(report: dict[str, Any]) -> None:
    """Print the human-readable report for one summary."""
    filters = report["filters"]
    print(f"Packets analyzed: {report['packet_count']}")
    if any(filters.values()):
        print(f"Packets read: {report['packets_read']}")
        active = ", ".join(f"{name}={value}" for name, value in filters.items() if value is not None)
        print(f"Filters: {active}")
    print(f"Total bytes: {report['total_bytes']}")

    print("\nCapture range:")
    if report["first_timestamp"] is None:
        print("  No packet timestamps observed.")
    else:
        print(f"  First packet: {format_timestamp(report['first_timestamp'])}")
        print(f"  Last packet:  {format_timestamp(report['last_timestamp'])}")
        print(f"  Duration: {format_seconds(report['duration_seconds'])}")
        rate = report["average_packets_per_second"]
        if rate is None:
            print("  Average rate: n/a (the capture spans no measurable time)")
        else:
            print(f"  Average rate: {rate:.2f} packets/s, {report['average_bytes_per_second']:.2f} bytes/s")

    for title, key in (
        ("Protocols", "protocols"),
        ("Bytes per protocol", "bytes_per_protocol"),
        ("Top sources", "top_sources"),
        ("Top destinations", "top_destinations"),
        ("Destination ports", "destination_ports"),
        ("DNS queries", "dns_queries"),
    ):
        print(f"\n{title}:")
        if not report[key]:
            print("  No observed values.")
        for value, count in report[key].items():
            print(f"  {printable(value)}: {count}")

    print("\nTop talkers by packets:")
    if not report["top_talkers_by_packets"]:
        print("  No observed values.")
    for talker in report["top_talkers_by_packets"]:
        print(f"  {printable(talker['host'])}: {plural(talker['packets'], 'packet')}, {plural(talker['bytes'], 'byte')}")

    print("\nTop talkers by bytes:")
    if not report["top_talkers_by_bytes"]:
        print("  No observed values.")
    for talker in report["top_talkers_by_bytes"]:
        print(f"  {printable(talker['host'])}: {plural(talker['bytes'], 'byte')}, {plural(talker['packets'], 'packet')}")

    print("\nTop flows by bytes:")
    if not report["top_flows"]:
        print("  No observed values.")
    for flow in report["top_flows"]:
        print(f"  {format_flow(flow)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize a real PCAP without retaining all packets in memory.")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--json", action="store_true", help="Print JSON instead of a human-readable report")
    parser.add_argument("--top", type=int, default=10, help="Entries to show in each ranking (default: 10)")
    parser.add_argument("--host", help="Only count packets sent to or from this address")
    parser.add_argument("--port", type=int, help="Only count packets using this source or destination port")
    parser.add_argument("--protocol", help="Only count packets of this protocol (TCP, UDP, IP, IPv6, OTHER)")
    args = parser.parse_args()
    if args.top < 1:
        raise SystemExit(f"--top must be at least 1, got {args.top}")
    if args.port is not None and not 0 <= args.port <= 65535:
        raise SystemExit(f"--port must be between 0 and 65535, got {args.port}")
    if not args.pcap.is_file():
        raise SystemExit(f"PCAP not found: {args.pcap}")
    filters = Filters(host=args.host, port=args.port, protocol=args.protocol)
    try:
        report = analyze_pcap(args.pcap, top=args.top, filters=filters)
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    if args.json:
        print(json.dumps(report, indent=2))
        return
    print_report(report)


if __name__ == "__main__":
    main()
