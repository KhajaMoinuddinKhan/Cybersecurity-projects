# Overview

SSL/TLS Scanner opens a verified TLS connection to a host and reports the negotiated TLS version, cipher, certificate subject, issuer, and expiry time. It uses Python's default certificate and hostname validation.

## A useful first exercise

Run against an endpoint you are authorized to inspect, then compare the reported expiry with its certificate details. Repeating the command after a certificate renewal is a useful practical check. A connection failure is also meaningful output: it means no verified session was established.

One successful handshake does not enumerate every cipher or protocol the server supports. A result can also differ across load-balancer nodes, Python builds, or certificate stores. This project does not assign a security grade, test obsolete protocols individually, or replace a full TLS configuration review.

[Back to the project guide](../README.md)
