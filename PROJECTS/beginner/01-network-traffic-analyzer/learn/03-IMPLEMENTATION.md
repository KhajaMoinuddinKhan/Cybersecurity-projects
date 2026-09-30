# Implementation

- `TrafficRecord` stores the fields used by the analyzer.
- Scapy imports stay inside the packet functions so the summary logic does not depend on Scapy at import time.
- `Counter` calculates protocol, source-host, and destination-port totals.
- DNS names are decoded as UTF-8 and trailing dots are removed in the summary.
- The command line reports a missing PCAP or missing Scapy dependency with a clear exit message.
