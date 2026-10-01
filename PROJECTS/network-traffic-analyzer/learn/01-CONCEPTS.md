# Concepts

IP identifies the network endpoints, TCP and UDP carry transport ports, and DNS questions expose requested names when the capture contains them. IPv4 and IPv6 use different Scapy layers, so both are checked. DNS response packets echoing a question are not requests and are excluded from the query counter.

Counters are a compact summary, not a risk score. The same observed value can be normal in one environment and unusual in another.
