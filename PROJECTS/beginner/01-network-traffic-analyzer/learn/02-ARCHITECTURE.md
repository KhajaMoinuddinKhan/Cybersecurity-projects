# Architecture

1. The command line accepts a PCAP path and checks that the file exists.
2. Scapy reads the capture and passes each packet to `packet_to_record()`.
3. `packet_to_record()` extracts the protocol, addresses, destination port, and DNS query when present.
4. `summarize_records()` counts the normalized records.
5. `print_summary()` writes the final report to the terminal.
