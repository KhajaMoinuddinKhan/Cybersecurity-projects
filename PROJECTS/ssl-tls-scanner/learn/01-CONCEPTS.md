# Concepts

- TLS protects network traffic after a successful handshake.
- Certificate-chain and hostname validation help confirm the server identity expected by the client.
- The negotiated TLS version and cipher describe the session that was established.
- Certificate subject, issuer, and expiry fields provide identity and validity context.

## Interpreting the evidence

A successful run prints the host, port, TLS version, cipher, certificate subject, issuer, and expiry in UTC. A certificate or hostname validation failure stops the inspection. The tool does not silently disable verification to produce a result.

One successful handshake does not enumerate every cipher or protocol the server supports. A result can also differ across load-balancer nodes, Python builds, or certificate stores. This project does not assign a security grade, test obsolete protocols individually, or replace a full TLS configuration review.

[Back to the project guide](../README.md)
