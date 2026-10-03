# Implementation

**Aggregation is `Counter` all the way down.** Protocols, protocol bytes, source hosts, source bytes, destination ports, port bytes, flows and flow bytes are each a `Counter` keyed by the thing being counted. There is no database and no intermediate structure, which keeps the memory cost proportional to the number of distinct values rather than to the number of packets.

**The flow key is a formatted string.** Building the five-tuple as `source:port -> destination:port PROTOCOL` means the flow counters serialise straight to JSON without a conversion step, and the keys are readable in the terminal. The cost is that the key is a string rather than a tuple, so anything that later wants to filter flows programmatically would have to parse it back. That trade was made deliberately for presentational simplicity at this scale.

**Length and timestamp come from the packet, defensively.** `len(packet)` gives the wire length, but an in-memory packet built by a test may not support it, so the call is guarded and falls back to zero. The timestamp is read with `getattr(packet, "time", None)` and coerced to a float, because Scapy's own time type is not a plain float on every version.

**The time range is computed during the same pass.** Rather than a second loop, the minimum and maximum timestamps are tracked as records are folded in. The duration is then the difference, clamped at zero so a capture whose timestamps are out of order cannot produce a negative interval.

**Rates are derived only when there is an interval.** If every record has no timestamp, the duration is `None` and both the human report and the JSON report say so instead of dividing by zero or printing a fabricated zero.

**Errors are specific.** A missing file, a missing Scapy install and an unreadable capture each produce their own message and a non-zero exit, rather than a traceback or an empty report that looks like a successful run on an empty capture.

**Tests build their own captures.** Most of the suite constructs `TrafficRecord` objects directly, which makes the counter arithmetic checkable by hand, and the remainder writes real PCAP files with Scapy so the packet-parsing path is exercised end to end. One test runs the CLI in a fresh interpreter to confirm the documented command works as documented.

[Back to the project guide](../README.md)
