# Implementation

Protocol detection checks TCP before UDP and falls back to IP or OTHER. Both transport ports are read, so a port filter can match either direction, while the destination-port ranking still reports destination ports only. DNS names are decoded with replacement for malformed bytes and trailing dots are normalized.

Byte accounting sums `len(packet)`, the captured frame length, for each counted packet. Flows are keyed by a tuple of the two addresses, the two ports and the protocol; only packets with both addresses open a flow, so a link-layer packet such as ARP adds to the protocol and byte totals but has no flow. Timestamps come from Scapy's packet clock; the earliest and latest become the capture range and the per-flow bounds.

Top lists are capped by `--top`, while the totals still cover the complete capture. Rankings are ordered by their own metric and broken deterministically by the other metric and then the key, so equal counts do not shuffle between runs. Derived floats such as durations and rates are rounded to six decimals to keep binary-float noise out of the JSON.

The JSON output uses string keys for destination ports so it can be consumed consistently by JavaScript and other JSON tools. Values taken from the capture, including addresses and protocols, are printed escaped in the human report so a crafted file cannot drive the terminal.

[Back to the project guide](../README.md)
