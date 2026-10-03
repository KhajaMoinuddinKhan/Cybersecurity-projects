# Concepts

**A capture format is a container, not a protocol.** A PCAP file holds frames with a timestamp, a recorded length and the bytes themselves. Everything this tool reports is derived from those three things plus the parsed headers, which is why the timestamps matter as much as the addresses.

**Wire length and captured length are different numbers.** Every capture record stores the number of bytes that were actually saved, which can be smaller than the frame on the wire when the capture was taken with a short snaplen. This project totals the recorded bytes. On a truncated capture that means the byte figures are a floor rather than a measurement, and it is worth knowing before you quote them.

**A flow is not a conversation.** The conventional flow definition is a unidirectional five-tuple: source address, source port, destination address, destination port, protocol. One TCP conversation therefore produces two flows, one in each direction, with independent byte counts. That is not a shortcoming; it is what makes per-direction accounting meaningful, because a request and a response are rarely the same size.

**Rates need a denominator.** Packets per second is meaningless without the interval it was measured over, and the interval here is the span between the first and last timestamp in the file. If the capture has a gap, the average covers the gap. If the file contains a single packet, there is no interval at all and no rate can be honestly reported.

**Counters are the whole algorithm.** Aggregation by key is enough to answer every question this tool asks. There is no model, no scoring and no statistics beyond the sum, which is why the code is short and why its output can be checked by hand.

**DNS names are observations, not attributions.** A name in the query list means some host in the capture asked for it. It does not mean the name is malicious, that the answer was used, or that the connection went anywhere.

[Back to the project guide](../README.md)
