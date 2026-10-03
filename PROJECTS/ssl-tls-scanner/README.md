# SSL/TLS Scanner

Ask a TLS endpoint what it will actually negotiate, which protocol versions and
cipher families it will still accept, what identity it presents, and what it
says about HSTS. The scanner opens a verified connection first; when the
certificate does not validate it re-opens the same connection without
verification so the certificate can still be read and reported. A validation
failure is never turned into a successful result: it is recorded and shown.

One scan answers nine questions:

- Which of TLS 1.0, 1.1, 1.2 and 1.3 does the server accept?
- Is the negotiated cipher weak, and will the server still negotiate weak cipher families?
- What is the full certificate chain, not only the leaf?
- What are the certificate's subject, issuer, serial, validity dates, key and signature algorithm?
- Is the certificate self-signed, and does its chain validate against this machine?
- Does the certificate actually match the hostname that was requested?
- Does the negotiated cipher provide forward secrecy?
- Does the HTTPS response carry `Strict-Transport-Security`, and with what `max-age`?
- Putting it together, a letter grade with the reasons behind it.

## Running it

Standard library only:

```console
python -m src.scanner example.com --port 443 --timeout 5
```

Pass a hostname, not a URL. The default port is 443 and the default timeout is
five seconds. Add `--json` to print the whole assessment as JSON, including the
per-certificate chain and every check:

```console
python -m src.scanner example.com --json
```

## Reading the output

```
host: github.com
port: 443
tls_version: TLSv1.3
cipher: TLS_AES_128_GCM_SHA256
forward_secrecy: True
certificate_subject: commonName=github.com
certificate_issuer: countryName=GB, organizationName=Sectigo Limited, commonName=Sectigo Public Server Authentication CA DV E36
certificate_expires: 2026-11-29T23:59:59+00:00

protocols:
  TLSv1.0: rejected (deprecated)
  TLSv1.1: rejected (deprecated)
  TLSv1.2: accepted
  TLSv1.3: accepted

cipher_weaknesses: none
offered_weak_ciphers: none detected

certificate_chain: 3 certificate(s)
  [0] subject=commonName=github.com | issuer=...Sectigo Public Server Authentication CA DV E36 | key=EC 256 | signature=ECDSA/SHA-256 | expires=2026-11-29T23:59:59+00:00
  [1] subject=...Sectigo Public Server Authentication CA DV E36 | issuer=...Sectigo Public Server Authentication Root E46 | key=EC 256 | signature=ECDSA/SHA-384 | expires=2036-03-21T23:59:59+00:00
  [2] subject=...Sectigo Public Server Authentication Root E46 | issuer=...USERTrust ECC Certification Authority | key=EC 384 | signature=ECDSA/SHA-384 | expires=2038-01-18T23:59:59+00:00

certificate:
  key_type: EC
  key_size: 256
  signature_algorithm: ECDSA/SHA-256
  subject_alt_names: github.com, www.github.com
  days_until_expiry: 57.1
  expiry_status: ok
  self_signed: False
  chain_valid: True
  hostname_matches: True

hsts:
  checked: True
  present: True
  max_age: 31536000
  include_subdomains: True

grade: A (score 100)
```

Expiry is printed in UTC in ISO 8601 form. A connection that cannot be
established is reported just as plainly, and it is the interesting case as often
as the success is:

```
TLS assessment failed: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: ...
TLS assessment failed: [WinError 10061] No connection could be made because the target machine actively refused it
TLS assessment failed: timed out
```

If the certificate does not validate, the scan does not stop; it records
`chain_valid: False` and the error text in `chain_error`, and reads the
certificate anyway so it can be reported.

## The grade

The grade is derived only from the checks this scanner actually performs, and
each point it removes is printed as a reason. The deductions are:

| Finding | Points |
| --- | --- |
| A deprecated protocol (TLS 1.0 or 1.1) is accepted | −25 each |
| The negotiated cipher is weak | −30 |
| The server accepts a weak cipher family | −10 each |
| The certificate has expired | −40 |
| The certificate expires within 7 / 30 days | −15 / −8 |
| An RSA key is under 2048 bits, or an EC key under 256 bits | −20 / −10 |
| The certificate is signed with SHA-1 or MD5 | −20 |
| The certificate is self-signed, or its chain does not validate | −30 (counted once) |
| The certificate does not match the requested hostname | −30 |
| The negotiated cipher has no forward secrecy | −15 |
| `Strict-Transport-Security` is missing, or its `max-age` is under 180 days | −5 |

The remaining score maps to A (90+), B (80+), C (70+), D (60+) and F (below
60). A check that could not be performed — a protocol the client library cannot
restrict to, a cipher family the client cannot offer, HSTS headers that could not
be fetched — is listed under `not_checked` and does not change the score. The
grade is a summary of the checks above and nothing else; a good grade is not a
statement that an endpoint is secure, and a bad grade names exactly which
checks failed.

## Argument handling

`--port` must be between 0 and 65535, and `--timeout` must be a positive, finite
number of seconds. Both are checked at the command line, where a bad value exits
with the usage message, and again inside `scan()` for callers who use it as a
library. That second check matters on Windows in particular: an out-of-range
port passed straight to the socket layer can wrap around and connect to an
unrelated port instead of failing, which is a confusing way to learn that you
mistyped a number.

## What a scan does not tell you

- **It is a point-in-time assessment.** Results depend on the endpoint, the load-balancer node that answered, the network and this Python build. Repeating the scan is the only way to see change.
- **Cipher-family coverage is bounded by the client.** Weak families are found by offering only that family's ciphers and seeing whether the server completes the handshake. The Python/OpenSSL build used here exposes no RC4, 3DES, DES, NULL, EXPORT or MD5 suites at all, so those families are reported as `not probed` rather than as "not supported". Only anonymous (ADH/AECDH) suites could be probed on this build. `SSLSocket.shared_ciphers()` returns `None` on this runtime, so the full list of suites the server offers cannot be enumerated directly.
- **Chain validity is judged against this machine's trust store.** A certificate signed by a private or corporate CA that this machine does not trust shows `chain_valid: False`, the same as an outright self-signed certificate.
- **TLS 1.3 is treated as forward secret.** Every TLS 1.3 suite is used with an ephemeral key exchange by default, and the suite name alone does not carry the key exchange; TLS 1.2 and below are judged from the suite name (ECDHE/DHE/EDH).
- **HSTS is read from one `HEAD /` response.** The header is only meaningful over HTTPS, and a redirect or a CDN edge may answer differently from the origin.
- **Protocol probes relax the client's own limits.** To reach TLS 1.0 and 1.1 the probe sets the OpenSSL security level to 0 and offers the full cipher list, so "accepted" means the server completed a handshake at that version with a permissive client.
- It does not enumerate every cipher the server supports, test certificate revocation, inspect the application behind TLS, or replace a full configuration review.

## Tests

```console
python -m pytest -q tests
```

Tests cover cipher-family classification, forward-secrecy detection, certificate
parsing from DER, hostname matching, expiry bands, the grading rules, the
verified-then-unverified connection flow, and a full scan against a local
self-signed TLS server that the tests start themselves (no internet needed).
