# Challenges

- The result depends on the network and the endpoint state at scan time.
- One connection reports one negotiated session rather than every server-supported option.
- Certificate details can change after renewal or infrastructure changes.
- The project does not grade protocol policy or enumerate remote configuration.

## Working within the scope

One successful handshake does not enumerate every cipher or protocol the server supports. A result can also differ across load-balancer nodes, Python builds, or certificate stores. This project does not assign a security grade, test obsolete protocols individually, or replace a full TLS configuration review.

Run against an endpoint you are authorized to inspect, then compare the reported expiry with its certificate details. Repeating the command after a certificate renewal is a useful practical check. A connection failure is also meaningful output: it means no verified session was established.

[Back to the project guide](../README.md)
