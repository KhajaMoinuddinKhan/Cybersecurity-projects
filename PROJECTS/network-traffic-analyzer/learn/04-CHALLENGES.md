# Challenges

A PCAP is a record of one observation point, not the whole network. VLANs, encapsulation, truncated packets, encryption, and capture loss can limit the fields available. Streaming reduces memory pressure but does not reduce the time needed to inspect each packet.

Byte totals inherit every gap in the capture. A snaplen-truncated frame contributes only the bytes that were stored, and the on-wire size it lost is not reconstructed, so a byte total is a floor rather than an exact wire volume. A flow's duration is the span between its first and last captured packet, which understates how long the conversation ran whenever packets were dropped. The average rates describe only the interval between the first and last packet and hide whatever bursts happened inside it.

Grouping by the 5-tuple as written on the wire also means the two directions of one connection are reported as two flows, and a conversation spread across several ports appears as several flows. Before interpreting a busy endpoint, compare it with the capture scope, time window, and expected application behavior.

[Back to the project guide](../README.md)
