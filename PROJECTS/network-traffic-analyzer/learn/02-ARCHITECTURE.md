# Architecture

Scapy's `PcapReader` produces packets incrementally. `packet_record()` translates one packet into a small immutable record. `summarize()` consumes those records and retains counters instead of the packet list. The CLI chooses JSON or human-readable presentation after analysis.

This separation keeps the aggregation logic testable without requiring a live interface or a large capture file.
