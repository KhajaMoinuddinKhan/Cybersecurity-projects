# Network Traffic Analyzer

This is the streaming sibling of [PCAP Traffic Summary](../pcap-traffic-summary). Both answer the same basic question, but this one reads a capture packet by packet instead of loading it, and it can print its report as JSON so another local tool can consume it.

Where the summary tool counts packets, this one also accounts for bytes, groups packets into conversations, and puts the capture on a timeline. Reach for it when the capture is large, when you want the numbers in a form you can pipe somewhere else, or when you need to know who talked to whom rather than only who appeared most often.

## Running it

```console
python -m src.analyzer capture.pcap
python -m src.analyzer capture.pcap --json
python -m src.analyzer capture.pcap --top 5
python -m src.analyzer capture.pcap --host 192.168.1.50 --port 53
python -m src.analyzer capture.pcap --protocol udp
```

## The two output modes

The human-readable report is meant for a quick look in a terminal:

```
Packets analyzed: 10
Total bytes: 834

Capture range:
  First packet: 2026-01-01T00:00:00Z
  Last packet:  2026-01-01T00:00:03Z
  Duration: 3.000 s
  Average rate: 3.33 packets/s, 278.00 bytes/s

Protocols:
  TCP: 5
  UDP: 3
  IP: 1
  OTHER: 1

Bytes per protocol:
  TCP: 450
  UDP: 268
  IP: 74
  OTHER: 42

Top sources:
  192.168.1.50: 5
  93.184.216.34: 2
  8.8.8.8: 1
  2001:db8::50: 1

Top destinations:
  192.168.1.50: 3
  93.184.216.34: 3
  8.8.8.8: 2
  2001:db8::53: 1

Destination ports:
  53: 2
  443: 2
  40000: 1
  50000: 1
  80: 1
  50001: 1

DNS queries:
  example.test: 1
  cdn.example.test: 1

Top talkers by packets:
  192.168.1.50: 8 packets, 696 bytes
  93.184.216.34: 5 packets, 450 bytes
  8.8.8.8: 3 packets, 246 bytes
  2001:db8::50: 1 packets, 96 bytes
  2001:db8::53: 1 packets, 96 bytes

Top talkers by bytes:
  192.168.1.50: 696 bytes, 8 packets
  93.184.216.34: 450 bytes, 5 packets
  8.8.8.8: 246 bytes, 3 packets
  2001:db8::50: 96 bytes, 1 packets
  2001:db8::53: 96 bytes, 1 packets

Top flows by bytes:
  192.168.1.50:50000 -> 93.184.216.34:443 TCP: 2 packets, 228 bytes, 0.200 s
  8.8.8.8:53 -> 192.168.1.50:40000 UDP: 1 packets, 100 bytes, 0.000 s
  2001:db8::50:50000 -> 2001:db8::53:53 UDP: 1 packets, 96 bytes, 0.000 s
  93.184.216.34:443 -> 192.168.1.50:50000 TCP: 1 packets, 94 bytes, 0.000 s
  192.168.1.50:- -> 8.8.8.8:- IP: 1 packets, 74 bytes, 0.000 s
  93.184.216.34:80 -> 192.168.1.50:50001 TCP: 1 packets, 74 bytes, 0.000 s
  192.168.1.50:40000 -> 8.8.8.8:53 UDP: 1 packets, 72 bytes, 0.000 s
  192.168.1.50:50001 -> 93.184.216.34:80 TCP: 1 packets, 54 bytes, 0.000 s
```

A talker is any address that appears at either end of a packet, so the same host can be a source and a destination. The two talker rankings show the same hosts ordered by packets and by bytes, because a host that sends many small packets and a host that sends one large one are not the same finding. A flow is one direction of a 5-tuple conversation (`src ip`, `src port`, `dst ip`, `dst port`, `protocol`); the reverse direction is counted separately, and a missing port is shown as `-`.

`--json` prints the same report as an object. The original keys (`packet_count`, `protocols`, `top_sources`, `top_destinations`, `destination_ports`, `dns_queries`) keep their packet counts, and the new fields carry the byte and flow detail:

```json
{
  "packet_count": 10,
  "packets_read": 10,
  "total_bytes": 834,
  "first_timestamp": 1767225600.0,
  "last_timestamp": 1767225603.0,
  "duration_seconds": 3.0,
  "average_packets_per_second": 3.333333,
  "average_bytes_per_second": 278.0,
  "protocols": { "TCP": 5 },
  "bytes_per_protocol": { "TCP": 450 },
  "top_sources": { "192.168.1.50": 5 },
  "top_destinations": { "192.168.1.50": 3 },
  "destination_ports": { "53": 2 },
  "dns_queries": { "example.test": 1 },
  "top_talkers_by_packets": [ { "host": "192.168.1.50", "packets": 8, "bytes": 696 } ],
  "top_talkers_by_bytes": [ { "host": "192.168.1.50", "packets": 8, "bytes": 696 } ],
  "top_flows": [
    {
      "source": "192.168.1.50",
      "source_port": 50000,
      "destination": "93.184.216.34",
      "destination_port": 443,
      "protocol": "TCP",
      "packets": 2,
      "bytes": 228,
      "first_timestamp": 1767225600.5,
      "last_timestamp": 1767225600.7,
      "duration_seconds": 0.2
    }
  ],
  "filters": { "host": null, "port": null, "protocol": null }
}
```

This example was run with `--top 1`, so each ranking holds a single entry; without `--top` each ranking holds up to ten. Timestamps are Unix epoch seconds as read from the capture.

## Filtering and ranking

Three options restrict the report to the packets you care about. They combine with AND:

- `--host ADDRESS` keeps packets whose source or destination is that address.
- `--port PORT` keeps packets whose source or destination port is that number.
- `--protocol NAME` keeps packets of that protocol, matched without regard to case (`tcp`, `UDP`, `ipv6`).

Filtering happens while the capture is streamed, so a filtered run still reads every packet but only counts the matches. When a filter is active the report also shows `Packets read` (everything seen) next to `Packets analyzed` (everything counted), and repeats the active filters:

```
Packets analyzed: 2
Packets read: 10
Filters: host=192.168.1.50, port=53
Total bytes: 172
```

`--top N` sets how many entries each ranking shows; the totals (`Packets analyzed`, `Total bytes`, the capture range) always cover the whole capture regardless of `--top`.

## How it works

`analyze_pcap()` opens Scapy's `PcapReader` and hands one packet at a time to `packet_record()`, which extracts the fields the report needs: the protocol, the two addresses, both ports, any DNS questions, the captured frame length, and the capture timestamp. `summarize()` consumes those records and keeps counters and per-flow running totals, so memory use is tied to the number of distinct addresses, names and flows rather than to the size of the capture. The reader is closed when the scan finishes.

The packet handling follows the same rules as the summary tool:

- Only the packet's own outer transport decides the protocol, the destination port, and any DNS name. A header quoted inside an ICMP error, or carried inside an IP tunnel, is payload and is ignored.
- Every DNS question in a packet is counted, not just the first.
- Packets with no transport of their own are counted as `IP`, `IPv6`, or `OTHER`.
- A name that carries control characters is printed escaped, so a crafted capture cannot rewrite your terminal; the `--json` report escapes them as `\u001b` in the usual way. Addresses and protocols are escaped the same way when printed.

Byte counts are the captured frame lengths Scapy reports, which include the link-layer header. A flow is only created when a packet has both a source and a destination address, so a link-layer packet such as ARP appears in the protocol and byte totals but not in the flow list. The capture range is the earliest and latest packet timestamp seen; the average rates divide the totals by that duration, and are reported as `n/a` when the capture spans no measurable time.

One ordering detail matters if you ever extend this code: Scapy only knows how to map a capture's link type (DLT 1 to Ethernet, for example) once the matching layer module has been imported. If the reader is created before that happens, it silently falls back to raw bytes and every packet is reported as `OTHER` with no addresses or ports at all. `analyze_pcap()` therefore imports the layer modules first, and a test runs the documented command in a fresh interpreter so the ordering cannot regress.

## Limits

The analyzer describes traffic; it does not judge it. Nothing here decrypts, reassembles streams, or identifies a person. A capture can miss traffic, and an address that appears often is a question to investigate rather than an answer.

The numbers are as good as the capture, not better. Bytes are the captured frame sizes, so a snaplen-truncated frame contributes only the bytes that were actually stored, and the on-wire size it lost is not reconstructed. A flow's duration is the span between its first and last captured packet, which is a lower bound on how long the conversation really lasted when packets were dropped. The average rates describe the span between the first and last packet only; they say nothing about bursts inside it, and a capture of one packet has no rate at all. Grouping is strictly by the 5-tuple as written on the wire, so the two directions of one connection are two flows.

## Tests

```console
python -m pytest -q tests
```

The suite covers aggregation over known packet records, an empty capture, a real capture read from disk, a snaplen-truncated frame, a fresh-interpreter run of the CLI, ICMP-quoted and tunnelled headers, and multiple DNS questions. It also checks byte totals and per-protocol bytes, the two talker orderings, 5-tuple flow grouping with per-flow time and totals, the capture time range and rates, the `--host`/`--port`/`--protocol` filters, and the `--top` cap.
