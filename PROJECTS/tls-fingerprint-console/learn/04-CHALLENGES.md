# Challenges

Four defects were found by running the console over a real capture, and three of them share a shape worth naming: every rule was correct in isolation and dead in the integrated system.

**first_seen could never fire.** The ingest endpoint stored each event before it evaluated the rules, and `first_seen` asks the store whether it has already seen a fingerprint value. Because the value had just been written, the answer was always yes, and the rule that was supposed to announce a new value was silent on every value that ever arrived. The fix was to evaluate the rules first and store afterwards, which is a one-line reordering with a consequence far larger than its size.

**os_mismatch could never fire.** The rule compares the operating system a User-Agent declares against the operating system mapped from the event's JA3, and it needs that mapping handed to it. The application never built or supplied the map, so the rule had nothing to compare against and returned nothing on every event. The fix was to derive the map from the corpus and pass it into the evaluation context.

**known_bad could never fire.** The rule was written to fire when an event already carried an intel verdict, on the assumption that something upstream would attach one. Nothing did, so the rule waited forever for a field that was never set. The fix was to have the rule consult the corpus itself, so a fingerprint that matches the malware list raises the alert regardless of what the caller remembered to attach.

**A TLS record could be parsed as an HTTP request.** The HTTP parser accepted any byte stream whose first line was non-empty. A TLS record begins `0x16 0x03`, which is not a request line and not empty, so the parser accepted it and produced a JA4H computed from a record header rather than from a request. The pipeline compounded it by handing whole TLS streams to the same parser. The fix was to validate the request line strictly — exactly a method, a target and a version, with the method on a known list and the version matching `HTTP/x.y` — so a stream that is not an HTTP request is rejected rather than misread.

What makes these worth recording is that the unit tests passed throughout. Each rule had been tested against a hand-built event and a stub context, and against those inputs every rule behaved. The defects lived in the seams — in the order two calls were made, in a context key that was never populated, in a dependency the caller was expected to supply and did not. The response was an integration suite that drives the real store, corpus and rules through the real endpoint and asserts that every rule can fire through the app, because a rule that only fires under a stub is not a working rule.

## The boundaries

The limits are part of the design, not apologies for it. The console never decrypts, so it fingerprints only the handshake and a JA4H can only ever describe a plaintext HTTP flow. Capture is offline: it reads a pcap or accepts posted events, and there is no live interface, which means the tool sees what someone chose to record and nothing more. The capture reader covers Ethernet and raw-IP link types across pcap and pcapng, with IPv4, IPv6 and VLAN decoding, and does not attempt link types outside that set.

The reference set ages. It is a snapshot of two public feeds plus a few curated entries, it is not refreshed automatically, and a malicious fingerprint absent from it will not match — so the console's silence is never evidence that a client is clean. `os_mismatch` cannot separate macOS from Linux, because a JA3 names a TLS stack and the two often share one, so the rule treats the Unix family as consistent and fires only on a real contradiction between families. `ua_mismatch` depends on a built-in table of client families and produces no verdict for a fingerprint it does not recognise, preferring silence to a guess. And the certificate parsing behind JA4X is hand-written to the published examples and the common structure of a certificate, not to every extension an X.509 certificate can carry.

None of these is a defect to be fixed later; they are the honest edges of a passive, offline, structure-based tool. The console states them where it states what it can do, so a reader can weigh a match against what the tool could not have seen.

[Back to the project guide](../README.md)
