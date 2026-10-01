# SSL/TLS Scanner

Ask a TLS endpoint what it will actually negotiate with a normal, verifying client, and print the answer. That is a narrower question than "is this server secure", and it is one you can answer without guessing: the negotiated protocol version, the cipher suite, and the identity and expiry of the certificate the server presented.

Verification is never disabled to make a result appear. If the certificate does not validate, the scan stops and says so.

## Running it

Standard library only:

```console
python -m src.scanner example.com --port 443 --timeout 5
```

Pass a hostname, not a URL. The default port is 443 and the default timeout is five seconds.

## Reading the output

```
host: localhost
port: 8444
tls_version: TLSv1.3
cipher: TLS_AES_256_GCM_SHA384
certificate_subject: commonName=127.0.0.1
certificate_issuer: commonName=Hermes Test CA
certificate_expires: 2026-10-03T21:47:00+00:00
```

Expiry is printed in UTC in ISO 8601 form. A failure is reported just as plainly, and it is the interesting case as often as the success is:

```
TLS inspection failed: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate
TLS inspection failed: timed out
```

An untrusted certificate, a hostname mismatch, a refused connection and a timeout each produce their own message. None of them is silently turned into a successful scan.

## Argument handling

`--port` must be between 0 and 65535, and `--timeout` must be a positive, finite number of seconds. Both are checked at the command line, where a bad value exits with the usage message, and again inside `scan()` for callers who use it as a library. That second check matters on Windows in particular: an out-of-range port passed straight to the socket layer can wrap around and connect to an unrelated port instead of failing, which is a confusing way to learn that you mistyped a number.

## What one scan does not tell you

This describes a single handshake, at one moment, with one client. It is not a configuration audit. It does not enumerate the cipher suites the server supports, check certificate chain completeness, test protocol downgrade behaviour, look at HSTS or other headers, or say anything about the applications behind the TLS layer. A clean result means this client, at this time, negotiated this session.

## Tests

```console
python -m pytest -q tests
```

Tests cover certificate formatting, session behaviour with controlled connection objects, the refusal to continue when verification fails, and the port and timeout bounds.
