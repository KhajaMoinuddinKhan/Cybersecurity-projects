# Network Traffic Analyzer

This is the streaming sibling of [PCAP Traffic Summary](../pcap-traffic-summary). Both answer the same basic question, but this one reads a capture packet by packet instead of loading it, and it can print its report as JSON so another local tool can consume it.

Reach for this version when the capture is large, or when you want the numbers in a form you can pipe somewhere else.

## Running it

Scapy is the only dependency:

```console
python -m pip install -r requirements.txt
python -m src.analyzer capture.pcap
python -m src.analyzer capture.pcap --json
```

## The two output modes

The human-readable report is meant for a quick look in a terminal:

```
Packets analyzed: 13

Protocols:
  TCP: 6
  UDP: 5
  IP: 1
  OTHER: 1

Top sources:
  192.168.1.50: 6
  8.8.8.8: 2
  2001:db8::50: 2

Destination ports:
  443: 4
  53: 2

DNS queries:
  example.test: 1
  cdn.example.test: 1
```

`--json` prints the same report as an object with `packet_count`, `protocols`, `top_sources`, `top_destinations`, `destination_ports` and `dns_queries`, which is the mode to use from a script.

## How it works

`analyze_pcap()` opens Scapy's `PcapReader` and hands one packet at a time to `packet_record()`, which extracts the fields the report needs. `summarize()` keeps counters, so memory use is tied to the number of distinct addresses and names rather than to the size of the capture. The reader is closed when the scan finishes.

The packet handling follows the same rules as the summary tool:

- Only the packet's own outer transport decides the protocol, the destination port, and any DNS name. A header quoted inside an ICMP error, or carried inside an IP tunnel, is payload and is ignored.
- Every DNS question in a packet is counted, not just the first.
- Packets with no transport of their own are counted as `IP`, `IPv6`, or `OTHER`.

One ordering detail matters if you ever extend this code: Scapy only knows how to map a capture's link type (DLT 1 to Ethernet, for example) once the matching layer module has been imported. If the reader is created before that happens, it silently falls back to raw bytes and every packet is reported as `OTHER` with no addresses or ports at all. `analyze_pcap()` therefore imports the layer modules first, and a test runs the documented command in a fresh interpreter so the ordering cannot regress.

## Limits

The analyzer describes traffic; it does not judge it. Nothing here decrypts, reassembles streams, or identifies a person. A capture can miss traffic, and an address that appears often is a question to investigate rather than an answer.

## Tests

```console
python -m pytest -q tests
```

The suite covers aggregation over known packet records, an empty capture, a real capture read from disk, a snaplen-truncated frame, a fresh-interpreter run of the CLI, ICMP-quoted and tunnelled headers, and multiple DNS questions.
