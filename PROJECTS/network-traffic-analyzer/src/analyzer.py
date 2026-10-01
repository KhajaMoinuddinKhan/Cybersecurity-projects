"""Stream a PCAP into a compact, input-driven network report."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
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


def summarize(records: Iterable[PacketRecord]) -> dict[str, Any]:
    """Aggregate packet records without retaining the complete capture."""
    packets = 0
    protocols: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    ports: Counter[int] = Counter()
    dns_queries: Counter[str] = Counter()
    for record in records:
        packets += 1
        protocols[record.protocol] += 1
        if record.source: sources[record.source] += 1
        if record.destination: destinations[record.destination] += 1
        if record.destination_port is not None: ports[record.destination_port] += 1
        # Every question counts; one packet can ask more than one name.
        for name in (record.dns_queries or ((record.dns_query,) if record.dns_query else ())):
            dns_queries[name.rstrip(".")] += 1
    return {
        "packet_count": packets,
        "protocols": dict(protocols.most_common()),
        "top_sources": dict(sources.most_common(10)),
        "top_destinations": dict(destinations.most_common(10)),
        "destination_ports": {str(k): v for k, v in ports.most_common(10)},
        "dns_queries": dict(dns_queries.most_common(20)),
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


def packet_transport(packet: Any) -> Any:
    """Return the packet's own transport layer, or None.

    A capture can nest IP headers (a tunnel) or quote one inside an ICMP error.
    Those inner headers are payload rather than live traffic, so only the outer
    transport should decide the protocol, port and DNS names.
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
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    source = destination = None
    if IP in packet:
        source, destination = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        source, destination = packet[IPv6].src, packet[IPv6].dst

    # Only the packet's own transport counts; a header quoted by an ICMP error
    # or carried inside a tunnel belongs to a different packet.
    transport = packet_transport(packet)

    protocol, port = "OTHER", None
    if isinstance(transport, TCP):
        protocol, port = "TCP", port_number(transport.dport)
    elif isinstance(transport, UDP):
        protocol, port = "UDP", port_number(transport.dport)
    elif source:
        protocol = "IPv6" if IPv6 in packet else "IP"

    questions: tuple[str, ...] = ()
    if transport is not None and DNS in transport and transport[DNS].qr == 0:
        questions = dns_question_names(transport[DNS])

    return PacketRecord(protocol, source, destination, port, questions[0] if questions else None, questions)


def analyze_pcap(path: Path) -> dict[str, Any]:
    """Read a PCAP incrementally and return its observed report."""
    try:
        from scapy.error import Scapy_Exception
        load_scapy_layers()  # must run before the reader is created
        from scapy.utils import PcapReader
        with PcapReader(str(path)) as reader:
            return summarize(packet_record(packet) for packet in reader)
    except ImportError as exc:
        raise RuntimeError("Scapy is required; install requirements.txt") from exc
    except (OSError, ValueError, Scapy_Exception) as exc:
        raise ValueError(f"Could not read PCAP {path}: {exc}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize a real PCAP without retaining all packets in memory.")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--json", action="store_true", help="Print JSON instead of a human-readable report")
    args = parser.parse_args()
    if not args.pcap.is_file(): raise SystemExit(f"PCAP not found: {args.pcap}")
    try: report = analyze_pcap(args.pcap)
    except (RuntimeError, ValueError) as exc: raise SystemExit(str(exc)) from exc
    if args.json:
        print(json.dumps(report, indent=2))
        return
    print(f"Packets analyzed: {report['packet_count']}")
    for title, key in (("Protocols", "protocols"), ("Top sources", "top_sources"), ("Top destinations", "top_destinations"), ("Destination ports", "destination_ports"), ("DNS queries", "dns_queries")):
        print(f"\n{title}:")
        if not report[key]: print("  No observed values.")
        for value, count in report[key].items(): print(f"  {value}: {count}")


if __name__ == "__main__":
    main()
