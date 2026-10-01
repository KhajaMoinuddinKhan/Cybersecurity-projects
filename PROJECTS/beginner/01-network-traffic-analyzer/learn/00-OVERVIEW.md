# Overview

Network Traffic Analyzer reads a PCAP file with Scapy and converts packets into a small record model. It reports packet count, protocol totals, source hosts, destination ports, and DNS queries for quick network review.

## A useful first exercise

Start with a capture containing one DNS question and its reply. Expect two packets but one DNS query. Add a TCP connection and check that its destination port appears separately. This makes it easier to distinguish transport counts from application-level observations.

This is a traffic summary, not an intrusion detector. A busy host or unusual port needs context before you can call it suspicious. Encrypted application content stays encrypted, and DNS names are available only when the capture exposes them. Scapy loads the capture into memory, so large captures may need to be split before analysis.

[Back to the project guide](../README.md)
