# Concepts

- PCAP files store captured network packets for later analysis.
- TCP, UDP, IP, and DNS fields provide useful context without reading application payloads.
- IPv4 and IPv6 packets use different network-layer fields, so the parser handles both.
- Counters turn packet records into protocol, host, and destination-port summaries.
- DNS query names can help explain what systems tried to reach.
