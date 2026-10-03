"""Turn a packet capture into events the dashboard can see.

The other packet tools in this repository answer "what is in this capture" and
print a report. This module answers a different question: "what should the SIEM
know about this capture", and writes flows into the same store as the host
events, so a connection and a process can be joined on host and time.

One event is written per flow rather than per packet. A capture of any real size
contains far more packets than an analyst can read, and a flow record with a
packet count and a byte count is what a firewall or a NetFlow export would give
you.
"""
from __future__ import annotations

import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FLOW_CHANNEL = "network"
PCAP_SOURCE = "pcap"

# Ports that identify a service often enough to be worth naming in the message.
SERVICE_PORTS = {
    "20": "ftp-data",
    "21": "ftp",
    "22": "ssh",
    "23": "telnet",
    "25": "smtp",
    "53": "dns",
    "80": "http",
    "110": "pop3",
    "135": "msrpc",
    "139": "netbios",
    "143": "imap",
    "389": "ldap",
    "443": "https",
    "445": "smb",
    "1433": "mssql",
    "3306": "mysql",
    "3389": "rdp",
    "5432": "postgres",
    "5900": "vnc",
    "8080": "http-alt",
}


class PcapError(ValueError):
    """The capture cannot be read, or Scapy is not installed."""


def _scapy():
    try:
        from scapy.all import DNS, DNSQR, IP, IPv6, TCP, UDP, PcapReader
        from scapy.error import Scapy_Exception
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise PcapError(
            "Reading a capture needs Scapy. Run: python -m pip install -r requirements.txt"
        ) from exc
    return PcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR, Scapy_Exception


def _address(packet: Any, IP: Any, IPv6: Any) -> tuple[str, str]:
    if IP in packet:
        return str(packet[IP].src), str(packet[IP].dst)
    if IPv6 in packet:
        return str(packet[IPv6].src), str(packet[IPv6].dst)
    return "", ""


def _ports(packet: Any, TCP: Any, UDP: Any) -> tuple[str, str, str]:
    if TCP in packet:
        return str(packet[TCP].sport), str(packet[TCP].dport), "TCP"
    if UDP in packet:
        return str(packet[UDP].sport), str(packet[UDP].dport), "UDP"
    return "", "", "OTHER"


def _dns_queries(packet: Any, UDP: Any, DNS: Any, DNSQR: Any) -> list[str]:
    """Every DNS question in the packet, not just the first."""

    if UDP not in packet or not packet.haslayer(DNS):
        return []
    layer = packet[DNS]
    if int(getattr(layer, "qr", 0) or 0) == 1:
        return []

    names: list[str] = []
    question = getattr(layer, "qd", None)
    if question is None:
        return names
    try:
        entries = list(question) if isinstance(question, list) else [question]
    except TypeError:
        entries = [question]
    for entry in entries:
        name = getattr(entry, "qname", None)
        if name is None:
            continue
        text = name.decode("utf-8", "replace") if isinstance(name, bytes) else str(name)
        names.append(text.rstrip("."))
    return [name for name in names if name]


def _service(destination_port: str) -> str:
    return SERVICE_PORTS.get(destination_port, "")


def read_capture(path: Path) -> dict[str, Any]:
    """Aggregate a capture into flows and DNS queries.

    Returns ``{"flows": [...], "dns": [...], "packets": n, "unreadable": n}``.
    A packet whose headers cannot be read is counted and skipped rather than
    aborting the import.
    """

    PcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR, ScapyException = _scapy()

    flows: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    dns_names: dict[str, dict[str, Any]] = {}
    packets = 0
    unreadable = 0

    try:
        reader_context = PcapReader(str(path))
    except (ScapyException, EOFError, OSError, ValueError) as exc:
        raise PcapError(
            f"{path.name} is not a capture this tool can read: {exc}"
        ) from exc

    with reader_context as reader:
        for packet in reader:
            packets += 1
            try:
                source, destination = _address(packet, IP, IPv6)
                sport, dport, protocol = _ports(packet, TCP, UDP)
            except (AttributeError, IndexError, TypeError):
                unreadable += 1
                continue

            if not source and not destination:
                unreadable += 1
                continue

            key = (source, destination, sport, dport, protocol)
            entry = flows.setdefault(
                key,
                {
                    "source": source,
                    "destination": destination,
                    "source_port": sport,
                    "destination_port": dport,
                    "protocol": protocol,
                    "packets": 0,
                    "bytes": 0,
                    "first_seen": None,
                    "last_seen": None,
                },
            )
            entry["packets"] += 1
            entry["bytes"] += len(bytes(packet))

            when = getattr(packet, "time", None)
            if when is not None:
                stamp = datetime.fromtimestamp(float(when), tz=timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                if entry["first_seen"] is None:
                    entry["first_seen"] = stamp
                entry["last_seen"] = stamp

            for name in _dns_queries(packet, UDP, DNS, DNSQR):
                record = dns_names.setdefault(
                    name, {"name": name, "queries": 0, "first_seen": None}
                )
                record["queries"] += 1
                if record["first_seen"] is None and entry["first_seen"]:
                    record["first_seen"] = entry["first_seen"]

    return {
        "flows": sorted(
            flows.values(),
            key=lambda item: (-item["packets"], item["source"], item["destination"]),
        ),
        "dns": sorted(dns_names.values(), key=lambda item: item["name"]),
        "packets": packets,
        "unreadable": unreadable,
    }


def _format_bytes(count: int) -> str:
    if count < 1024:
        return f"{count} B"
    if count < 1024 * 1024:
        return f"{count / 1024:.1f} KB"
    return f"{count / (1024 * 1024):.1f} MB"


def flow_payloads(
    summary: dict[str, Any],
    *,
    host: str | None = None,
    capture_name: str = "",
) -> list[dict[str, Any]]:
    """Convert an aggregated capture into SIEM events."""

    machine = host or socket.gethostname()
    payloads: list[dict[str, Any]] = []

    for flow in summary["flows"]:
        service = _service(flow["destination_port"])
        label = f" ({service})" if service else ""
        destination = flow["destination"] or "unknown"
        port = flow["destination_port"] or "-"
        message = (
            f"{flow['protocol']} {flow['source']}:{flow['source_port'] or '-'} -> "
            f"{destination}:{port}{label}, {flow['packets']} packet(s), "
            f"{_format_bytes(flow['bytes'])}"
        )
        payloads.append(
            {
                "timestamp": flow["last_seen"] or flow["first_seen"],
                "channel": FLOW_CHANNEL,
                "provider": f"pcap:{capture_name}" if capture_name else "pcap",
                "event_id": "FLOW",
                "level": "Information",
                "severity": "Low",
                "username": "unknown",
                "host": machine,
                "source_ip": flow["source"] or "unknown",
                "message": message,
                "record_id": "",
                "source": PCAP_SOURCE,
                "is_alert": False,
                "rule_name": "",
                "external_id": (
                    f"pcap:{capture_name}:{flow['protocol']}:{flow['source']}:"
                    f"{flow['source_port']}:{flow['destination']}:{flow['destination_port']}:"
                    f"{flow['first_seen']}"
                ),
                "raw_log": flow,
                "fields": {
                    "protocol": flow["protocol"],
                    "source_address": flow["source"],
                    "destination_address": flow["destination"],
                    "source_port": flow["source_port"],
                    "destination_port": flow["destination_port"],
                    "packets": str(flow["packets"]),
                    "bytes": str(flow["bytes"]),
                    "capture": capture_name,
                },
            }
        )

    for record in summary["dns"]:
        payloads.append(
            {
                "timestamp": record["first_seen"],
                "channel": FLOW_CHANNEL,
                "provider": f"pcap:{capture_name}" if capture_name else "pcap",
                "event_id": "DNS",
                "level": "Information",
                "severity": "Low",
                "username": "unknown",
                "host": machine,
                "source_ip": "unknown",
                "message": f"DNS query for {record['name']} ({record['queries']} time(s))",
                "record_id": "",
                "source": PCAP_SOURCE,
                "is_alert": False,
                "rule_name": "",
                "external_id": f"pcap:{capture_name}:dns:{record['name']}",
                "raw_log": record,
                "fields": {
                    "protocol": "DNS",
                    "query_name": record["name"],
                    "queries": str(record["queries"]),
                    "capture": capture_name,
                },
            }
        )

    return payloads


def ingest_capture(
    db_path: Path,
    capture_path: Path,
    *,
    host: str | None = None,
    limit: int = 5000,
) -> dict[str, Any]:
    """Read a capture and store it as events. Returns a summary of what happened."""

    from .app import ingest_payloads

    if not capture_path.is_file():
        raise PcapError(f"Capture not found: {capture_path}")

    summary = read_capture(capture_path)
    payloads = flow_payloads(summary, host=host, capture_name=capture_path.name)
    stored = payloads[:limit]
    inserted = ingest_payloads(db_path, stored, PCAP_SOURCE)

    return {
        "capture": capture_path.name,
        "packets_read": summary["packets"],
        "unreadable_packets": summary["unreadable"],
        "flows": len(summary["flows"]),
        "dns_names": len(summary["dns"]),
        "events_offered": len(payloads),
        "events_stored": len(stored),
        "inserted": inserted,
        "truncated": len(payloads) > len(stored),
    }
