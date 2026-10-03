# Challenges

- The result depends on the network and the endpoint state at scan time, and different load-balancer nodes can answer differently.
- Cipher-family coverage is bounded by the client library: a family it cannot offer is reported as `not probed`, not as unsupported. The Python/OpenSSL build used here exposes no RC4, 3DES, DES, NULL, EXPORT or MD5 suites, so only anonymous suites could be probed.
- `SSLSocket.shared_ciphers()` returns `None` on this runtime, so the full list of suites the server offers cannot be enumerated directly.
- Chain validity is judged against this machine's trust store, so a private CA that is not installed here reads the same as a self-signed certificate.
- Certificate details can change after renewal or infrastructure changes.
- TLS 1.3 is treated as forward secret, because its suite names do not carry the key exchange.

## Working within the scope

The grade is derived only from the checks this scanner runs, and every deduction is
printed as a reason. Checks that could not be performed are listed under
`not_checked` and do not change the score. This is a point-in-time assessment, not
a complete audit: it does not enumerate every cipher, test certificate revocation,
or say anything about the applications behind the TLS layer. Run it against an
endpoint you are authorized to inspect, read the reasons rather than the letter,
and repeat it after changes. A connection failure is also meaningful output: it
means no verified session was established.

[Back to the project guide](../README.md)
