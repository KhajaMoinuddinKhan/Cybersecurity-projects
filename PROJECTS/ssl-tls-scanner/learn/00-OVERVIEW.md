# Overview

SSL/TLS Scanner opens a TLS connection to a host and assesses it. It starts with
a verified connection, and when the certificate does not validate it re-opens the
connection without verification so the certificate can still be read and
reported. It then probes each protocol version the client can restrict to, looks
for weak cipher families the server will still negotiate, walks the full
certificate chain, checks the hostname and forward secrecy, reads the HSTS
header, and derives a letter grade from the checks it actually performed.

## What a run produces

For a reachable endpoint the scan reports the negotiated version and cipher, which
of TLS 1.0, 1.1, 1.2 and 1.3 the server accepts, the full chain with each
certificate's subject, issuer, serial, dates, key and signature algorithm, whether
the leaf is self-signed, whether the chain validates, whether the hostname
matches, whether the cipher has forward secrecy, and the HSTS header. The grade
lists every reason behind it. `--json` prints all of it in machine-readable form.

## A useful first exercise

Run against an endpoint you are authorized to inspect and read the grade's
reasons rather than the letter. Repeating the command after a certificate renewal
or a configuration change is the practical check, because a single scan is a
snapshot of one connection, one load-balancer node, and one Python build. A
connection failure is also meaningful output: it means no verified session was
established. The grade summarizes the checks this tool runs; it is not a
guarantee that the endpoint is secure.

[Back to the project guide](../README.md)
