# Architecture

The pipeline has four stages and no state between them.

1. **The command line** parses the capture path, `--json` and `--top`, checks that the file exists, and rejects a nonsensical `--top` before doing any work.
2. **`analyse_pcap()`** hands the file to Scapy's `rdpcap()` and turns every packet into a `TrafficRecord`.
3. **`packet_to_record()`** walks the packet's own layers and extracts the protocol, both addresses, both ports, the wire length, the capture timestamp and any DNS question names.
4. **`summarize_records()`** folds those records into counters, and `print_summary()` or `as_json_report()` presents them.

## The record model

`TrafficRecord` is a frozen dataclass holding exactly the fields the report needs: protocol, source and destination addresses, source and destination ports, the first DNS question and the full tuple of questions, the wire length and the timestamp. Freezing it keeps the aggregation honest — nothing downstream can mutate a record as it is counted — and keeping it flat means the counters never need to know anything about Scapy.

Scapy imports live inside the packet functions rather than at module scope. That keeps the summary logic importable, and testable, on a machine where Scapy is not installed, which matters because Scapy's import path touches network interface discovery in some environments.

## Presentation

`print_summary()` and `as_json_report()` read the same dictionary. The human report adds formatting, singular and plural wording and the `--top` limit; the JSON report converts the counters into plain dictionaries and adds the derived rates. Because both read one structure, the two outputs cannot drift apart.

Every value that comes out of the capture — addresses, flow keys, DNS names — is passed through `printable()` before it reaches the terminal. A capture is attacker-controlled input, and a DNS name containing escape sequences would otherwise be able to clear the screen or rewrite what the analyst is looking at.

[Back to the project guide](../README.md)
