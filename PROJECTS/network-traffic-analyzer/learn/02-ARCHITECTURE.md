# Architecture

Scapy's `PcapReader` produces packets incrementally. `packet_record()` translates one packet into a small immutable record carrying the protocol, addresses, both ports, DNS questions, the captured frame length, and the timestamp. `summarize()` consumes those records and retains counters plus one running `FlowState` per 5-tuple instead of the packet list. The CLI chooses JSON or human-readable presentation after analysis.

Filtering lives in `summarize()` rather than in the reader, so a filtered run still streams every packet but only folds the matches into the report. `packets_read` records how many were seen and the active filters are echoed back, which keeps a restricted report from being mistaken for a complete one.

This separation keeps the aggregation logic testable without requiring a live interface or a large capture file: the tests feed `summarize()` plain records with known sizes and timestamps, and only the end-to-end tests touch a real capture.

[Back to the project guide](../README.md)
