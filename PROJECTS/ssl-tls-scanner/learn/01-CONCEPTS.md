# Concepts

- TLS protects network traffic after a successful handshake.
- The protocol version and cipher suite describe the session that was established; older versions and some suites are considered weak.
- Certificate-chain and hostname validation help confirm the server identity expected by the client.
- A certificate carries a subject and issuer, a serial number, a validity window, a public key and a signature algorithm, and usually a list of subject alternative names.
- HSTS is an HTTP response header that tells a browser to use HTTPS for a period of time.

## Interpreting the evidence

A weak cipher is recognized from its name: RC4, 3DES, plain DES, NULL encryption,
EXPORT-grade ciphers, anonymous key exchange, and MD5-based suites are all flagged.
Forward secrecy is present when the negotiated suite uses an ephemeral (EC)DHE key
exchange, which is why a suite name containing `ECDHE` or `DHE` matters. A
certificate is self-signed when its issuer equals its subject, and a chain
"validates" when this machine's trust store accepts it; those are related but not
identical, because a certificate from an untrusted private CA fails validation
without being self-signed.

## The grade

The grade is a summary of the checks this scanner performs, and every deduction is
printed as a reason. Checks that could not be performed are listed separately and
do not affect the score. A high grade means the specific checks below passed; it is
not a statement that the endpoint is secure, and a low grade names exactly which
checks failed.

[Back to the project guide](../README.md)
