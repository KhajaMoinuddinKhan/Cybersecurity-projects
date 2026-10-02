# PCAP Traffic Summary

A capture file is one of the few places where you can see what a network actually did, rather than what you assume it did. This tool reads a PCAP you already have and turns it into a short summary: which protocols appear, who sent the most packets, which destination ports were used, and which DNS names were asked for.

It is a reading tool, not a capture tool. It never opens an interface, never generates traffic, and never fetches a sample capture for you. You point it at a file and it tells you what is in it.

## Running it

Install Scapy in the same environment you use for the command:

```console
python -m pip install -r requirements.txt
python -m src.analyze_pcap capture.pcap
```

There are no other options. Use a capture taken on a network you are authorised to inspect, ideally from a lab or your own machine.

## What the output looks like

Running it against a small lab capture with DNS, HTTPS, HTTP, ICMP, ARP and IPv6 traffic gives this:

```
Packets analysed: 13

Protocols:
  TCP: 6
  UDP: 5
  IP: 1
  OTHER: 1

Top source hosts:
  192.168.1.50: 6 packets
  8.8.8.8: 2 packets
  2001:db8::50: 2 packets

Top destination ports:
  443: 4 packets
  53: 2 packets
  80: 1 packets

DNS queries:
  example.test
  cdn.example.test
```

Every number here was observed in the file. An empty capture prints zeroes and "No observed values" instead of inventing something to show.

## How it reads a packet

`packet_to_record()` pulls the fields the summary needs out of one Scapy packet, and `summarize_records()` counts them as they arrive.

Two details are worth knowing because they are easy to get wrong:

- **A packet is described by its own outer transport.** An ICMP error message quotes the header that caused it, and a tunnel carries a whole second IP header inside the first. Those inner headers are payload, not traffic. If you count them you end up reporting a DNS name that was never sent on the wire, and labelling an IP-in-IP tunnel as UDP. The code walks the outer payload chain and stops at a nested IP header or an ICMP layer.
- **A DNS packet can ask more than one question.** All of them are reported, not just the first.

Packets with no transport layer of their own are counted as `IP` (IPv4 or IPv6) or `OTHER` (ARP and anything else unrecognised).

A name that carries control characters is printed escaped, so a crafted capture cannot clear your screen or rewrite what you see. The JSON report escapes the same characters itself.

## What it cannot tell you

A frequent address or port is a lead, not a conclusion. The summary describes what was recorded and nothing more: encrypted payloads stay encrypted, and traffic that was never captured cannot appear. A capture taken at one point on one machine is a partial view of the network, and reading it as a complete record is the most common way to draw the wrong conclusion.

## Tests

```console
python -m pytest -q tests
```

The tests build their own captures with Scapy and check the counters against known packet sets, including a DNS query and reply, a truncated frame, an ICMP error that quotes a DNS query, and a packet asking two questions at once.
