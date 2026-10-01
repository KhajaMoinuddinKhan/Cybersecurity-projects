# Implementation

- `TrafficRecord` stores the fields used by the analyzer.
- Scapy imports stay inside the packet functions so the summary logic does not depend on Scapy at import time.
- `Counter` calculates protocol, source-host, and destination-port totals.
- DNS names are decoded as UTF-8 and trailing dots are removed in the summary.
- The command line reports a missing PCAP or missing Scapy dependency with a clear exit message.

## Inputs and failure handling

Supply an existing PCAP file captured in your own lab. The program reads the file; it does not start a capture or transmit packets. Install the dependencies in `requirements.txt` before running it.

If Scapy is missing, install `requirements.txt` in the same Python environment you use to run the command. A missing or unreadable capture produces an error instead of an empty report. Some restricted containers block Scapy while it discovers network interfaces; run the analyzer on your workstation or a runner that permits that initialization.

[Back to the project guide](../README.md)
