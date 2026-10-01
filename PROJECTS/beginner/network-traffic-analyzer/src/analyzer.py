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
        if record.dns_query: dns_queries[record.dns_query.rstrip(".")] += 1
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

    protocol, port = "OTHER", None
    if TCP in packet:
        protocol, port = "TCP", port_number(packet[TCP].dport)
    elif UDP in packet:
        protocol, port = "UDP", port_number(packet[UDP].dport)
    elif source:
        protocol = "IPv6" if IPv6 in packet else "IP"

    query = None
    if DNS in packet and packet[DNS].qr == 0 and DNSQR in packet:
        raw = packet[DNSQR].qname
        if raw is not None:
            text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
            query = text.strip() or None
    return PacketRecord(protocol, source, destination, port, query)


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
