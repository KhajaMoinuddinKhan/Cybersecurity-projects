# Implementation

- `_main_handshake()` tries `ssl.create_default_context()` first and falls back to `_unverified_context()` only on `SSLCertVerificationError`, returning both the chain and whether verification succeeded.
- `_chain_der()` reads `get_unverified_chain()` (falling back to `get_verified_chain()` and then `getpeercert(binary_form=True)`) and returns the DER bytes of every certificate.
- A minimal DER reader (`_der_tlv`, `_der_children`, `_der_oid`, `_der_time` and friends) decodes each certificate: subject and issuer, serial, validity, public key type and size, signature algorithm, and subject alternative names.
- `probe_protocol()` sets both `minimum_version` and `maximum_version` on a context to force one version, relaxing the OpenSSL security level so TLS 1.0 and 1.1 can still be reached.
- `probe_weak_cipher_families()` lists the ciphers the client can offer, groups them by weak family, and tries to negotiate each family on its own.
- `cipher_families()` and `cipher_is_forward_secret()` classify suites by name; `hostname_matches()` matches the requested name against DNS and IP subject alternative names with RFC 6125 single-label wildcards.
- `grade_assessment()` walks the collected result, records a reason and a point value for each finding, and lists any check it could not perform under `not_checked`.

## Inputs and failure handling

Provide a hostname, not a full URL. The default port is 443 and the default
timeout is five seconds. A connection that cannot be established is reported as
`TLS assessment failed: ...`, and a certificate that does not validate is reported
in the result instead of stopping the scan. For timeouts, check the hostname, port,
connectivity, and firewall before increasing `--timeout`. If a private lab uses its
own certificate authority, configure the appropriate trusted CA in your
environment. Do not treat a verification failure as a reason to remove validation
from the code.

[Back to the project guide](../README.md)
