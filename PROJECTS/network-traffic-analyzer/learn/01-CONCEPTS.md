# Concepts

IP identifies the network endpoints, TCP and UDP carry transport ports, and DNS questions expose requested names when the capture contains them. IPv4 and IPv6 use different Scapy layers, so both are checked. DNS response packets echoing a question are not requests and are excluded from the query counter.

Counting packets and counting bytes answer different questions. A host that sends many small packets is busy; a host that sends one large packet moves more data. The report therefore ranks hosts, which it calls talkers, twice: once by packets and once by bytes. A talker is any address at either end of a packet, so a host that both sends and receives is counted once with both directions combined.

A flow is one direction of a 5-tuple conversation: source address, source port, destination address, destination port, and protocol. The reverse direction is a separate flow because the tuple is different. Each flow carries its own packet count, byte count, first and last timestamp, and duration, which is what turns a pile of packets into something that looks like a conversation.

The capture range is the earliest and latest packet timestamp in the file, and the duration between them is what the average rates divide by. A rate is only meaningful across a span, so a capture of a single packet has no rate.

Counters are a compact summary, not a risk score. The same observed value can be normal in one environment and unusual in another.

[Back to the project guide](../README.md)
