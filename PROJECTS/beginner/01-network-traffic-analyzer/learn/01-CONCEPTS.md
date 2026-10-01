# Concepts

- PCAP files store captured network packets for later analysis.
- TCP, UDP, IP, and DNS fields provide useful context without reading application payloads.
- IPv4 and IPv6 packets use different network-layer fields, so the parser handles both.
- Counters turn packet records into protocol, host, and destination-port summaries.
- DNS query names can help explain what systems tried to reach.

## Interpreting the evidence

The report shows the total number of packets, protocol counts, the ten busiest source addresses, the ten most common destination ports, and up to twenty DNS question names. Repeated names remain repeated because they represent separate queries. DNS replies are excluded from the query list, although they still contribute to packet and protocol totals.

This is a traffic summary, not an intrusion detector. A busy host or unusual port needs context before you can call it suspicious. Encrypted application content stays encrypted, and DNS names are available only when the capture exposes them. Scapy loads the capture into memory, so large captures may need to be split before analysis.

[Back to the project guide](../README.md)
