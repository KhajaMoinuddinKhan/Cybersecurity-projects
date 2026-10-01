# Architecture

1. The command line accepts a PCAP path and checks that the file exists.
2. Scapy reads the capture and passes each packet to `packet_to_record()`.
3. `packet_to_record()` extracts the protocol, addresses, destination port, and DNS query when present.
4. `summarize_records()` counts the normalized records.
5. `print_summary()` writes the final report to the terminal.

## Follow one run

`packet_to_record()` extracts the fields used by the report and puts them in a `TrafficRecord`. IPv4 and IPv6 addresses are supported. TCP and UDP packets retain their destination ports; other IP traffic falls back to `IP`, and unrecognized traffic to `OTHER`. `summarize_records()` uses counters to aggregate those records, while `print_summary()` handles presentation.

Supply an existing PCAP file captured in your own lab. The program reads the file; it does not start a capture or transmit packets. Install the dependencies in `requirements.txt` before running it.

[Back to the project guide](../README.md)
