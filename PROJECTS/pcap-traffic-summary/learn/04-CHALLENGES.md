# Challenges

**Inner headers that look like traffic.** The single hardest correctness problem here is that a packet can contain another packet. An ICMP error quotes the header that caused it, and a tunnel carries an entire second IP header inside the first. Scapy's convenient accessors return the *first* layer of a given type wherever it appears, so `packet[IP]` on an IPv6 packet carrying an IPv4 tunnel hands back the inner header — the wrong one. The fix is to walk the payload chain from the outside in and stop at the first network layer, which is what `outer_network_layer()` does. Getting this wrong does not crash anything; it silently reports a DNS name that was never sent on the wire, which is far worse.

**The same trap for transport.** `packet_transport()` has to stop at a nested IP header or an ICMP layer rather than keep walking, because the UDP header inside a quoted ICMP error belongs to a different packet entirely. Without that guard, an ICMP port-unreachable message is counted as UDP traffic to port 53.

**More than one DNS question.** A DNS packet can carry several questions, and Scapy exposes them either as a list or as a chain hanging off the first entry depending on how the packet was built. Both shapes are walked. Assuming a single question is the common shortcut and it silently drops data.

**Truncated frames.** A capture taken with a short snaplen stores partial frames, so a port number can be missing even though the address is present. The code treats a missing port as absent rather than inventing one, and the byte totals are honest about being a floor. This is also why the byte figures on a truncated capture should not be compared against a full one.

**Memory.** `rdpcap()` loads the entire file before anything is summarised, so a multi-gigabyte capture will exhaust memory on a workstation. The streaming sibling project exists precisely because of this: it reads the file one packet at a time and keeps only the counters, at the cost of not being able to answer questions that need the whole file.

**Attack input in the output.** Every address and name in the report came from a file that could have been crafted. A DNS name containing terminal escape sequences would otherwise be able to rewrite the analyst's screen, which is a real class of attack against security tooling. All captured values pass through an escaping function before printing.

**Rates that never happened.** Dividing packets by the capture duration produces a number that is arithmetically correct and operationally misleading whenever the capture has gaps. There is no fix inside this tool — the number is what it is — so the README says plainly that a rate describes the capture, not the link.

[Back to the project guide](../README.md)
