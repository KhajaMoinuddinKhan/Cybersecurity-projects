# Architecture

1. The command line accepts a host, port, timeout and an optional `--json` flag, and validates the port and timeout before anything connects.
2. A verified TLS connection is opened first. If the certificate does not validate, the same connection is opened again without verification so the identity can still be read, and the verification error is kept.
3. Every certificate the server presented is parsed from its DER bytes.
4. One connection per protocol version attempts a handshake restricted to TLS 1.0, 1.1, 1.2 and 1.3.
5. For each weak cipher family the client library can offer, one connection tries to negotiate only that family.
6. One connection fetches the HTTPS response headers for HSTS.
7. The hostname, forward secrecy and expiry are computed from what was collected.
8. A grade is derived from the checks that were performed.
9. The result is printed as text, or as JSON with `--json`.

## Follow one run

`socket.create_connection()` opens TCP and an SSL context wraps it. The verified
attempt uses `ssl.create_default_context()`, so the certificate and hostname are
checked exactly as a normal client would check them. Only if that raises a
certificate-verification error does the scanner retry with an unverified context
to read the chain, and the error is reported rather than discarded. The chain
comes from `get_unverified_chain()`, and each certificate is decoded with a small
DER reader in the module, so no third-party library is needed. The protocol and
cipher probes each open their own short-lived connection, and the HSTS check
sends a `HEAD /` request over one more.

Provide a hostname, not a full URL. The default port is 443 and the default
timeout is five seconds. This command makes real network connections, so its
output depends on the endpoint and your network. The implementation uses the
Python standard library and needs no project-specific package installation.

[Back to the project guide](../README.md)
