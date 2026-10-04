# PCAP Traffic Summary

A capture file is one of the few places where you can see what a network actually did, rather than what you assume it did. This tool reads a PCAP you already have and turns it into a short summary: how much traffic there was, which protocols carried it, which hosts and ports moved the most, which conversations took place, and which DNS names were asked for.

It is a reading tool, not a capture tool. It never opens an interface, never generates traffic, and never fetches a sample capture for you. You point it at a file and it tells you what is in it.

## Running it

```console
python -m src.analyze_pcap capture.pcap
python -m src.analyze_pcap capture.pcap --json
python -m src.analyze_pcap capture.pcap --top 5
```

`--json` prints the same report as a JSON object, and `--top` controls how many entries each ranking shows. Use a capture taken on a network you are authorised to inspect, ideally from a lab or your own machine.

## What the output looks like

Running it against a small lab capture with DNS, HTTPS, HTTP, ICMP, ARP and IPv6 traffic gives this:

```
Packets analysed: 13
Bytes analysed: 4218

Capture time:
  first:    2026-10-01T09:14:02.113000+00:00
  last:     2026-10-01T09:14:07.881000+00:00
  duration: 5.768s (2.3 packets/s, 731 bytes/s)

Protocols:
  TCP: 6 packets, 3410 bytes
  UDP: 5 packets, 620 bytes
  IP: 1 packet, 98 bytes
  OTHER: 1 packet, 90 bytes

Top source hosts by bytes (top 10):
  192.168.1.50: 3890 bytes in 8 packets
  8.8.8.8: 168 bytes in 2 packets

Top destination ports (top 10):
  443: 4 packets, 3010 bytes
  53: 2 packets, 168 bytes
  80: 1 packet, 400 bytes

Top flows by bytes (top 10):
  192.168.1.50:51422 -> 93.184.216.34:443 TCP: 3010 bytes in 4 packets
  192.168.1.50:52001 -> 8.8.8.8:53 UDP: 92 bytes in 1 packet

DNS queries:
  example.test
  cdn.example.test
```

Every number here was observed in the file. An empty capture prints zeroes and "No observed values" instead of inventing something to show.

## Why bytes and flows, not just packets

Packet counts alone are easy to misread. A host sending forty 60-byte acknowledgements looks busier than a host sending three 1,400-byte transfers, when in fact it moved far less data. The report therefore ranks hosts and protocols by **bytes** and shows the packet count beside them, so you can tell a chatty host from a heavy one.

The flow section goes further and groups packets into **unidirectional five-tuples** — source address and port, destination address and port, and protocol. That answers the question a list of addresses cannot: who was talking to whom. Because it is unidirectional, the two directions of one conversation appear as two separate flows, which is the convention the rest of the tooling world uses and which keeps the byte counts on each side honest.

The capture time range and the rates derived from it are worth a caution. A rate computed from a capture is the rate *in that capture*, not the rate on the link. A capture taken over five seconds with a two-second gap in the middle reports an average that never occurred at any instant.

## How it reads a packet

`packet_to_record()` pulls the fields the summary needs out of one Scapy packet, and `summarize_records()` counts them as they arrive.

Three details are worth knowing because they are easy to get wrong:

- **A packet is described by its own outer transport.** An ICMP error message quotes the header that caused it, and a tunnel carries a whole second IP header inside the first. Those inner headers are payload, not traffic. If you count them you end up reporting a DNS name that was never sent on the wire, and labelling an IP-in-IP tunnel as UDP. The code walks the outer payload chain and stops at a nested IP header or an ICMP layer.
- **A DNS packet can ask more than one question.** All of them are reported, not just the first.
- **Wire length is not captured length.** A capture taken with a short snaplen stores only the first part of each frame, so the byte totals here are the bytes that were *recorded*. On a truncated capture the byte figures understate the real traffic, and the report will still show the address and port because those sit in the part that was kept.

Packets with no transport layer of their own are counted as `IP` (IPv4 or IPv6) or `OTHER` (ARP and anything else unrecognised).

A name that carries control characters is printed escaped, so a crafted capture cannot clear your screen or rewrite what you see. The JSON report escapes the same characters itself.

## What it cannot tell you

A frequent address, a large flow or an unusual port is a lead, not a conclusion. The summary describes what was recorded and nothing more: encrypted payloads stay encrypted, and traffic that was never captured cannot appear. A capture taken at one point on one machine is a partial view of the network, and reading it as a complete record is the most common way to draw the wrong conclusion.

Nothing here inspects application payloads, reassembles TCP streams, or identifies a person. A flow tells you that two endpoints exchanged a quantity of bytes; it does not tell you what those bytes said.

## Tests

```console
python -m pytest -q tests
```

The tests build their own captures with Scapy and check the counters against known packet sets, including a DNS query and reply, a truncated frame, an ICMP error that quotes a DNS query, a packet asking two questions at once, the byte and flow totals, the capture time range and the `--top` and `--json` output.
