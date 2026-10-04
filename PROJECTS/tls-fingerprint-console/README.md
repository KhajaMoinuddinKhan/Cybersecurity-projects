# MKMK TLS Fingerprint Console

A TLS handshake is readable even though the session it opens is not. The ClientHello announces, in a fixed order, the protocol versions the client supports, its cipher suites, its extensions, its elliptic curves and its signature algorithms; the ServerHello answers with the version and cipher it chose and the extensions it will use. Those lists describe the TLS software itself, and two clients built on the same stack offer them in the same order. Reduce the lists to a short hash and you have a fingerprint: a name for the software that does not depend on the address it dialled, the certificate it was shown, or anything it did afterwards.

This console computes those fingerprints. It reads a packet capture, parses the TLS handshakes inside it, derives the JA3 and JA4+ fingerprints for each flow, matches them against a bundled threat-intelligence corpus, runs seven detection rules over the result, and serves a console that shows what it found. It reads a capture file, it can watch a live interface, or it accepts events posted to its API. It never decrypts the session: the handshake it reads is sent in the clear, and the one handshake that is not — a QUIC Initial packet — is readable anyway, because its keys are derived from a public salt and the connection ID rather than from any secret.

## Why fingerprints are worth computing

Identity and behaviour fail in opposite directions, and a fingerprint sits between them. A malware family rotates its infrastructure constantly — new addresses, new domains, new certificates — but it tends to keep the TLS stack it was built against, so a fingerprint that matched last month often matches today even when nothing else does. Run the same reasoning the other way and a different signal appears: one fingerprint offered by a hundred source addresses is one toolkit deployed across a hundred hosts, which is exactly the shape of an automated campaign and is invisible if you look only at destinations.

A fingerprint is also a description rather than a verdict. A JA4 value is not inherently good or bad; it is a name for a client, and whether that name means anything depends on what you compare it against. That is why the console keeps the corpus, the observed fingerprints and the alerts in separate views: the raw material, the reference set, and the rules' reading of the difference between them.

## Running it

The project needs Flask and pytest, and `cryptography` for the one job that needs a cipher: reading a QUIC Initial packet. The capture reader, the live-capture binding, the TLS parsers and the fingerprints themselves are all standard library. `cryptography` is imported guarded, so a machine without it still parses QUIC headers and reports the version and connection IDs — it simply cannot decrypt the Initial, and says so rather than pretending. Live capture additionally needs Npcap installed on the machine, which is a driver rather than a Python package.

```console
python -m pip install -r requirements.txt

python -m src.cli interfaces
python -m src.cli analyse capture.pcap
python -m src.cli demo
python -m src.cli watch
python -m src.cli serve
```

`analyse` reads a capture, fingerprints every flow it can, runs the rules and writes the events and alerts to a SQLite store. It prints the capture path, how many events and alerts were produced, and a line for each alert naming its severity, rule and title.

`demo` analyses a synthetic capture that the project builds itself, so you can see the console work without finding a real capture first. The capture is assembled by `fixtures/make_pcap.py` from hand-written pcap, Ethernet, IP, TCP, TLS and DER bytes, and contains a TLS handshake, a plaintext HTTP request and a UDP packet, which is enough to exercise every fingerprint kind the console knows.

`serve` starts the console on `http://127.0.0.1:5001` with a store at `tls_console.db` in the working directory. Both commands accept `--db` to point at a different store, and `serve` accepts `--port`. The console runs on the Flask development server bound to loopback; it is a lab tool, not a hardened service, and it should be reached over loopback or a network you control.

A useful first run is `demo` followed by `serve`: the demo fills the store, and the console then has events, fingerprints and alerts to display rather than six empty views.

## Live capture

The console can fingerprint handshakes as they happen on an interface, not only from a capture file. Two commands drive it, and the module behind them binds the capture driver directly, so live capture adds no Python dependency.

`interfaces` lists what this machine can capture from and says whether a capture driver is present at all:

```console
python -m src.cli interfaces
```

It reports whether a driver was found, the default filter, and one row per interface with an index, a human description and the device name, and it prints which interface it would choose by default. That default skips the pseudo-adapters Npcap lists — WAN Miniport, Wi-Fi Direct, virtual, Bluetooth and Teredo — because they carry no traffic, and prefers a real adapter.

`watch` captures live, fingerprints each handshake as the bytes arrive, and prints each event and alert as it happens:

```console
python -m src.cli watch
python -m src.cli watch --interface 3
python -m src.cli watch --interface "Wi-Fi" --filter "tcp port 443" --duration 30
```

`--interface` takes an index from the `interfaces` listing or a substring of an interface's description or device name. `--filter` replaces the default BPF expression, and `--duration` stops the run after that many seconds; without it, `watch` runs until you stop it. The default filter watches the ports a TLS handshake normally appears on — 443, 8443, 993, 995, 465, 587, 636, 853, 8883 and 9443 over TCP, and 443, 8443 and 8883 over UDP for QUIC — so the console follows handshakes rather than every packet on the wire, and follows HTTP/3 as well as TLS. As each event is released, `watch` prints the time, the client and server endpoints, the server name, one line for every fingerprint it computed, and the intel name when a fingerprint matches the corpus, with each alert printed beneath it.

Live capture needs two things the file and ingest paths do not. A capture driver must be installed: the module looks for Npcap's `wpcap.dll`, the driver Wireshark installs on Windows, and it says so plainly when the driver is absent instead of failing with an import error somewhere else. And opening an interface is a privileged operation, so `watch` normally needs an elevated shell. Neither is required for `analyse`, `demo`, `serve` or the ingest API.

The reason to watch live is that a fingerprint names a client rather than a destination. A short run against a real Wi-Fi adapter captured 1061 packets in 22 seconds and produced 51 flows, 19 fingerprinted events and 26 alerts, and the clearest thing it showed was one JA3 value — `a1ebe7f90a577e9399eaa60be3c67721` — appearing across eight different destinations: example.com, www.python.org, api.github.com, www.cloudflare.com, www.wikipedia.org, www.mozilla.org, duckduckgo.com and www.reddit.com. The same client library made all eight connections, and its TLS stack is the same wherever it dialled, so one fingerprint named all eight. The events from that run carried JA3, JA3S, JA4, JA4S and JA4T, and one flow carried a JA4X as well, read from its certificate. That is what client fingerprinting is for, and it is the thing to look for in your own runs.

How the live path works is worth one paragraph, because it cannot do what the file path does. A live packet arrives on its own and a ClientHello can be split across several TCP segments, so the console cannot wait for a whole capture to reassemble. Instead a sensor (`src/live.py`) keeps a table of in-flight flows and fingerprints each one as soon as enough bytes have arrived to try. It runs on the packet clock rather than the wall clock, so a replayed capture behaves like the live one it records. It emits a flow once the flow goes quiet — the server has answered and the flow has been idle for a short grace period, or a hard cap has passed — which is what lets the ServerHello and the Certificate both arrive before the event is released, so the server-side fingerprints are usually present. Every captured frame is decoded through the same decoder the capture-file reader uses, so a live packet and a recorded packet become identical packet dicts and the rest of the pipeline cannot tell them apart.

Because `watch` writes to a SQLite store and `serve` reads from one, the two can share the same `--db` and run at the same time: start the console, then start a capture against the same store, and events appear on the page as the store is written. The store opens in WAL mode, so a running capture does not block the console's reads.

## How a handshake becomes a fingerprint

The path from bytes to console is short enough to follow end to end. The file path is fully reproducible because it touches no network; the live path runs the same stages over packets as they arrive.

The capture reader (`src/pcap.py`) decodes classic pcap and pcapng into packet dicts, walking Ethernet II and raw-IP frames down through IPv4 or IPv6 and into TCP or UDP. It bounds-checks every low-level read, so a truncated or malformed capture raises a readable `ValueError` rather than a raw `struct.error`. The reassembler groups TCP payloads by direction — source address and port to destination address and port — orders each group by sequence number and concatenates it, dropping pure acknowledgements, so each direction becomes one contiguous byte stream.

The pipeline (`src/pipeline.py`) then buckets those streams into bidirectional flows and asks which direction carried a ClientHello; that direction is the client and the other is the server. It parses the ClientHello with `src/tls.py` and hands the field lists to `src/ja3.py` and `src/ja4.py`. On the server side it looks for a ServerHello and a Certificate message, and from the client's SYN it reads the TCP options for JA4T. When the client stream is not a TLS handshake at all, it tries to read it as a plaintext HTTP request, which is the one place a JA4H can come from. The file path now branches on transport before it does any of that: a capture is swept once for UDP, and every datagram that is a QUIC Initial the console can decrypt becomes its own event through the same ClientHello parser and the same JA3 and JA4 functions, before the TCP streams are reassembled into flows as they were. The live path branches the same way, sending a UDP datagram to the QUIC reader and a TCP segment to the flow table, so both front doors produce the same two kinds of event — one labelled `transport: tcp` and one labelled `transport: quic`.

One detail shapes every fingerprint and is worth stating before the definitions. Modern clients insert reserved values — `0x0a0a`, `0x1a1a`, and so on up to `0xfafa` — into their cipher, extension and curve lists. These are the GREASE values, and a server is required to ignore them. They are chosen afresh on every connection, so if a fingerprint kept them it would change from one handshake to the next and describe nothing. Every fingerprint module strips GREASE before it does anything else, which is why a client that pads its lists with GREASE produces the same value as one that does not.

## The seven fingerprints

The console computes seven fingerprints, five from the JA4+ family and two from Salesforce JA3. Each is a plain string; the two JA3 values are MD5 digests, and the JA4 family carry readable structure ahead of their hashes.

**JA3** is the original client fingerprint. It takes the protocol version, the cipher list, the extension list, the elliptic curves and the elliptic-curve point formats in the order the client sent them, writes the decimal values dash-separated inside each field and comma-separated between fields, and MD5-hashes the string. Because it preserves wire order, JA3 is sensitive to the exact ordering a stack chose, and two clients that offer the same suites in a different order get different JA3 values.

**JA3S** is the server's answer in the same idiom: the protocol version, the single chosen cipher and the extension list, in wire order, MD5-hashed.

**JA4** is the full client fingerprint and the one the console treats as a host's identity. Its first part is readable: a protocol character, a two-character version code, `d` or `i` for whether a server name was offered, the cipher count, the extension count and a two-character ALPN code. Then come two truncated SHA-256 hashes. The first is over the cipher list converted to lowercase four-digit hex, **sorted into hex order** rather than kept in wire order, so a client that shuffles its offer still lands on one value. The second is over the sorted extension list — with the SNI and ALPN extensions removed, since they are already represented in the readable part — followed by the signature algorithms in their original order. `ja4_r` returns the same fingerprint with the hashes left unhashed, which is useful when you want to see what went into a value rather than compare it.

**JA4S** is the server counterpart: protocol character, version, extension count and ALPN code, then the chosen cipher in hex and a truncated SHA-256 of the server's extensions in arrival order.

**JA4X** describes an X.509 certificate by its structure rather than its contents. It walks the certificate, collects the issuer's RDN attribute-type OIDs, the subject's, and the certificate's own extension OIDs, and produces three truncated SHA-256 hashes, one for each list. Because it hashes the DER-encoded OID bytes, two certificates issued by the same authority with the same extension profile share a JA4X even when the names, keys and dates differ — the shape of the certificate, not its subject.

**JA4T** describes the TCP stack from the SYN: the window size, the sequence of TCP option kinds, the maximum segment size and the window scale, joined into one readable string. It is a host fingerprint rather than a TLS one, and it is read from the client's SYN packet.

**JA4H** describes a plaintext HTTP client: the method and version as short codes, flags for whether a cookie and a referer were present, the header count and a language code, then three truncated SHA-256 hashes of the header names in order, the sorted cookie names, and the sorted cookie name-and-value pairs.

## QUIC and HTTP/3

QUIC is the transport HTTP/3 runs on, and it is not TLS over TCP — it is TLS 1.3 folded into a UDP protocol of its own. A sensor whose capture filter is TCP-only therefore sees none of it: the handshakes are on the wire, and the filter quietly excludes every one of them. The console watched only TCP until recently, which meant it was blind to HTTP/3 in proportion to how much of the web had moved to it.

The handshake inside a QUIC Initial packet is encrypted, and it is readable anyway, and the reason is worth stating plainly. The keys for a client Initial are derived from two things: a fixed salt that the specification publishes, and the destination connection ID that the client puts on the wire in the clear. Both are public, so a passive observer can derive the same keys and decrypt the same packet. This is not a weakness in QUIC; it is how the Initial works, because the connection ID has to be readable for the packet to be routed, and the handshake that follows is what establishes the real, secret keys. So "QUIC Initial decryption" means reading a packet whose keys were never secret from anyone who could see it.

A real ClientHello does not arrive in one packet, and that detail is the difference between a tool that passes its test and a tool that works. The RFC's own vector fits in a single Initial; traffic from an ordinary machine does not. A 1746-byte ClientHello observed on a live network arrived as 1211 bytes in the first Initial and the remaining 535 in the second, and a reader that looked at one datagram at a time found half a handshake every time and fingerprinted nothing. `CryptoAssembler` holds the CRYPTO stream per connection, keyed by the offset each frame declares, and reassembles from offset zero upwards — so a chunk whose offset does not join the run already held is discarded rather than spliced in, which is what stops decrypted padding from being mistaken for further frames. The handshake is emitted once the length in its own header says all of it has arrived.

`src/quic.py` does that reading. It parses the QUIC long header and its variable-length integers, derives the Initial secrets as RFC 9001 section 5.2 specifies, removes header protection the way section 5.4 lays out — the 16-byte sample taken at `pn_offset + 4`, run through AES-ECB to make a mask, with the low four bits of the first byte and the packet number XORed back — and decrypts the payload with the AEAD of section 5.3, where the nonce is the IV XORed with the packet number. QUIC version 1 (`0x00000001`) and version 2 (`0x6b3343cf`) are both supported; a packet of any other version is parsed for its header and connection IDs but not decrypted, because the salt differs and guessing it would be worse than saying so. The recovered ClientHello goes to the same `parse_client_hello` and the same `ja3` and `ja4` functions the TCP path uses, with the JA4 protocol character set to `q` rather than `t` — the leading character of a JA4 says which transport carried the handshake, and `q` is the QUIC code.

Whether the decryption is correct is not a matter of opinion, because the specification publishes a worked example and the acceptance test asserts it value by value. RFC 9001 Appendix A gives a complete protected client Initial packet together with every value it should produce: the initial secret, the client key, the IV and the header-protection key, the unprotected header, the packet number, and the exact ClientHello inside. The console reproduces all of them. The connection ID `8394c8f03e515708` yields initial secret `7db5df06…`, key `1f369613dd76d5467730efcbe3b1a22d`, IV `fa044b2f42a3fd3b46fb255c` and header-protection key `9f50449e04a0e810283a1e9933adedd2`; the protected packet decrypts to packet number 2 and a ClientHello byte-for-byte identical to the RFC's, which parses to SNI `example.com` and ALPN `alpn` and fingerprints as `q13d0211an_62ed6f6ca7ad_4d634acda6c0`. Nothing is mocked: the packet is really decrypted with the real HKDF and AES primitives.

The capture filter now covers both transports. The default BPF expression watches the TLS ports over TCP as before and adds UDP on 443, 8443 and 8883, so a `watch` run sees TLS and HTTP/3 handshakes alike. A QUIC event is labelled `transport: quic` and carries the QUIC version; a TCP event is labelled `transport: tcp`. Everything downstream treats them the same, because the fingerprint functions do not care which transport carried the bytes — a QUIC hello is parsed and hashed by the same code as a TCP one, and only the protocol character in the readable part records the difference.

## Encrypted Client Hello

Encrypted Client Hello is the extension a client offers when it wants the handshake itself to be private. With ECH, the outer ClientHello that a passive reader sees carries a public name in place of the real server name — a decoy, often a generic name shared by many sites — and the real extension list is sealed inside an encrypted inner ClientHello that only a server holding the right key can open. The outer hello still parses, because it has to: it is what the client and server negotiate the outer connection with. So a fingerprint can still be computed from it.

That fingerprint describes the outer shell, not the client. The extension set in an ECH outer hello is deliberately generic, and it may be padded or randomised precisely so that it does not distinguish one client from another; the SNI beside it is a public name rather than the site actually being visited. Presenting such a value as the client's fingerprint, with no qualification, would be a confidently wrong answer — the console would be handing over a value that looks like an identifier and names nothing. The console detects the extension (0xfe0d), reports `ech`, whether the outer hello parsed, and the config IDs it could read, and exposes `is_ech()` and `fingerprint_caveat()`. A seventh rule, `ech_obscured`, fires on any event flagged `ech`.

The extension is an offer, not a proof, and a run against the live wire is what settled the wording. Chrome offered ECH to ad networks and font hosts that publish no ECHConfig at all, shaping each offer like a real one — a well-formed outer structure, a random `config_id`, random `enc` and `payload` bytes. That is ECH GREASE, and it is deliberately indistinguishable from a real offer to anyone who is not looking up the destination's ECHConfig; only the DNS record would say which one a given handshake was, and the console does not look it up. So the rule's title is "an ECH offer may hide the handshake", and its detail names the extension, repeats the SNI it saw, and says plainly that the value may be a decoy rather than proof that the destination was hidden. The fingerprint is still shown, because it is still what was on the wire — but it is shown with the caveat attached, so a reader can weigh it rather than trust it.

## The intel corpus

The reference set lives under `data/corpus/` as JSON and is loaded offline; nothing is fetched at run time. Each entry names its kind, value, category, name, source and licence, and the console shows the source and licence beside every record so a match can be traced back to where it came from.

The bundled snapshot draws on three sources. The abuse.ch SSLBL JA3 blacklist contributes the malware fingerprints and is released under CC0-1.0. The salesforce/ja3 osx-nix client list contributes known client fingerprints and is released under BSD-3-Clause. A curated file carries a handful of entries under the project's own licence, including a Tor client fingerprint, Trickbot and Emotet JA3 values and a Trickbot JA3S. Across the three files the snapshot holds 258 records.

Lookup is exact and case-insensitive on the kind and value pair. A file that is missing, unreadable or not valid JSON is skipped rather than fatal, and the reason is recorded on the corpus, so a broken feed degrades the reference set instead of stopping the console.

## Identification with confidence

A corpus lookup answers one question — is this value known? — and real fingerprinting asks a softer one, because the useful cases are the near misses. A browser that updates from one version to the next keeps the same cipher list and the same extensions and changes only its build; a client behind a different server name presents the same TLS stack under a different name. An exact-match-or-nothing lookup reports nothing for all of those, which is the least useful answer available. `src/matcher.py` scores them instead.

An exact match on the kind and value is a confidence of `1.0`, and the matched entry is also the single candidate, so a positive answer always comes with something to point at. For a JA4 or a JA4S with no exact match, the matcher compares the two hashes that carry meaning. The `b` section is a truncated hash of the sorted cipher list and the `c` section is a truncated hash of the sorted extension list together with the signature algorithms; both describe the client's real cryptographic preferences rather than its build number, so they survive a version bump. Two values that share both score `0.8` — almost certainly the same TLS stack in a different build. One that shares the cipher hash only scores `0.5`, and one that shares the extension hash only scores `0.4`, each with a one-line basis sentence naming what was and was not shared. The candidates come back best-first, up to a small cap, so a caller sees the runner-up and not only the winner.

A JA3 miss is different on purpose. A JA3 is a single opaque MD5 over the whole pre-hash string, with no sections inside it to compare, so two JA3 values either match exactly or share nothing that can be scored. The matcher returns `0.0` and no candidate, with a basis that says a partial match is not meaningful, rather than manufacturing a number from a resemblance it cannot justify. A confidence that is not backed by structure is worse than no confidence, because it reads as evidence. The route that exposes all of this is `GET /api/match?kind=&value=`, which returns the match, the confidence, the basis and the candidates.

## The seven rules

The rules (`src/rules.py`) read each event and the context around it and decide whether it deserves attention. Each is a separate callable, and each is written to stay silent rather than guess when the information it needs is missing — an unknown fingerprint produces no verdict, not a default one.

- **known_bad** (critical) fires when a fingerprint on the event matches a corpus entry whose category is malware or c2. It consults the corpus itself rather than trusting a verdict someone else was supposed to attach.
- **ua_mismatch** (medium) fires when the declared User-Agent names a different client family from the one the fingerprint indicates — a `curl` user-agent behind a browser fingerprint, for instance. It uses a built-in table of well-known families and stays quiet when either side is unknown.
- **os_mismatch** (medium) fires when the User-Agent's declared operating system contradicts the operating system mapped from the event's JA3. It treats the whole Unix family as consistent, so it never invents a mismatch between two systems that share a TLS stack.
- **first_seen** (info) fires the first time a fingerprint value is observed. It asks the store whether the value has been seen before, which is why the ordering of evaluation and storage matters.
- **fp_rotation** (high) fires when one source address presents three or more distinct JA4 values for the same server name inside the window — the signature of a client deliberately changing its appearance.
- **monoculture** (medium) fires when one fingerprint value is presented by ten or more distinct source addresses inside the window, which points at one toolkit running on many hosts.
- **ech_obscured** (info) fires when the ClientHello offered Encrypted Client Hello. It is not a threat but a visibility limit: it says that the server name on the event is a public name rather than the real destination, and that the fingerprint describes the outer hello only, so the reader knows the value in front of them is not a reliable client identifier.

## Per-source diversity

Two sources can present the same number of fingerprints and mean opposite things. One host that makes a hundred connections and offers the same JA4 every time is a monoculture: one client, doing what it always does. Another host that makes a hundred connections and offers a different JA4 each time is rotating its appearance, which is the signature of a client that does not want to be followed. Counting events alone cannot tell them apart, so `src/matcher.py` also summarises how varied each source is.

`diversity()` reports, per source address, how many events it contributed, how many distinct JA4, JA3 and server names it presented, which JA4 is its most common, what share of its events carry that value, and a diversity figure between `0` and `1`. A source that offers one fingerprint every time scores near `0` with a dominant share near `1`; a source that never repeats scores `1.0`. The figure is the count of distinct JA4 values divided by the number of events, so it is read alongside the dominant share rather than instead of it — a source can be varied and still be dominated by one value if the rest are noise. The summary also lists the fingerprints shared by more than one source, which is the monoculture signal in numbers: one value, many addresses, the shape of a toolkit deployed across hosts rather than a client that is simply common. The route that exposes it is `GET /api/diversity`, which accepts a `limit` on how many recent events to summarise.

## Limits

These sit here, beside the description of what the console does, because they bound it and are as much a part of reading its output as the fingerprints are.

- **The session is never decrypted.** Only the handshake is fingerprinted. On TCP the handshake is sent in the clear; on QUIC it is encrypted, and the console reads it because an Initial packet's keys are public by design — but that is the Initial only. Everything after the handshake is protected with keys negotiated inside it, and the console cannot and does not touch it. JA4H therefore appears only for plaintext HTTP flows; a JA4H built from a TLS connection would be a fingerprint of ciphertext, and the console does not pretend otherwise.
- **Live capture needs a driver and, normally, an elevated shell.** The console can watch a live interface, but on Windows that requires Npcap, the capture driver Wireshark installs, and opening an interface is a privileged operation, so `watch` normally runs from an elevated shell. The file and ingest paths need neither, and a machine without a capture driver still gets the whole offline console.
- **The capture reader covers Ethernet and raw-IP link types.** pcap and pcapng are both supported, IPv4 and IPv6 are both decoded, and VLAN tags are followed, but other link-layer types are not, and a capture using one will be reported as such rather than guessed at.
- **The intel corpus is a snapshot.** It holds two public feeds plus a few curated entries, it is not updated automatically, and it will age. A fingerprint that is malicious and absent from the snapshot will not match, and freshness is the operator's responsibility, not the console's.
- **os_mismatch cannot separate macOS from Linux.** A JA3 identifies a TLS stack, and the two systems often share one. The rule treats the whole Unix family as consistent and fires only on a genuine contradiction between families.
- **ua_mismatch relies on a built-in table.** The table lists well-known client families and can be extended, but an unknown fingerprint produces no verdict rather than a guess, so the rule reports only the mismatches it can actually establish.
- **JA4X parsing is hand-written.** It follows the published examples by hashing DER-encoded OID bytes and walks the certificate structure directly, and it handles the common cases rather than every extension an X.509 certificate may carry.
- **ECH can be detected but not read into.** The console sees that a ClientHello offered Encrypted Client Hello and says so, but the real handshake is sealed inside an encrypted inner hello and stays sealed. What the console can offer is the caveat, not the fingerprint behind it.
- **QUIC decryption needs `cryptography`, and degrades without it.** Reading an Initial needs AES, which lives in the `cryptography` package. Without it the console still parses QUIC headers and reports the version and connection IDs, and says plainly that it cannot decrypt rather than pretending; the TCP path, the file path and the ingest path need no such package.
- **There is no JARM.** JARM is a different kind of fingerprint, computed by actively probing a server with a series of crafted ClientHellos; it needs to open connections, and this console only listens. It is not implemented, and it would not fit a tool that never transmits.
- **Alerts go to the store and the console and nowhere else.** There is no forwarding to a webhook, syslog or email; an alert is a row in the database and a line on the page, and getting it anywhere else is the operator's job.
- **The console has no access control.** It binds to loopback by default and has no login, no roles and no per-route permissions; anyone who can reach the port sees everything in the store. It is a lab tool and should be reached over loopback or a network you control.
- **There is no retention policy.** Events and alerts accumulate in the SQLite store until someone removes them; nothing ages out and nothing is pruned, so the store's size and the data in it are the operator's to manage.

## Privacy

TLS fingerprinting identifies client software without decrypting anything. It reads the handshake, which is public by design, and it needs no key to do it, so the absence of decryption is not the absence of privacy risk. What the console reads — the cipher lists, the extension order, the ALPN, the TCP options, the server name — is enough to say what software made the connection, and a fingerprint that is stable from one connection to the next can single out a device or a person across sites. Two connections from the same browser to two unrelated sites carry the same JA3 and JA4, which is exactly the property the console uses to name a client; the same property makes the fingerprint a tracking identifier. It survives clearing cookies, because nothing is stored on the client at all, and it can be used to defeat privacy tooling: someone behind a VPN, a proxy or a private-browsing window still carries their client's fingerprint, and a network that fingerprints handshakes can tell that the same device sits behind two different addresses.

This is not a flaw to be patched; it is what the technique is. Some clients resist it deliberately. Browsers randomise or pad parts of their ClientHello, and Encrypted Client Hello exists precisely to hide the real handshake from a passive reader; a fingerprint of a randomised or ECH connection is correspondingly less reliable, which is why the console reports the ECH caveat rather than a value that looks authoritative. But resistance is uneven, and most software does not attempt it. An operator who runs this on a network they do not own, or on traffic that is not their own, should weigh what they are collecting against who is on the wire. A handshake fingerprint is a description of a person's software, and on a network that carries other people's traffic — a shared office, a conference, an ISP — collecting it is a decision about those people rather than a neutral technical choice. The console does not transmit traffic and does not decrypt sessions, and neither of those facts makes the fingerprint harmless. It is worth saying plainly, because a tool that identifies people from their handshake is a tool that can be used to identify people, and the person running it is the one who decides whether that is appropriate.

## The console

The console is one self-contained HTML file (`src/templates/console.html`) with inline CSS and JavaScript and no external assets, CDN references or webfonts. That last exclusion is deliberate twice over: a tool that reads other people's handshakes has no business announcing itself to a font server, and the page has to render with the network unplugged. It polls the API about every two seconds and keeps filter and search input in place across re-renders, so a refresh does not throw away what you typed. The layout is a single dark deck — a top bar carrying the name, the seven views, the interface under capture and a UTC clock; a masthead carrying the headline counters, an **ingest sample** button and the time of the last refresh; and a footer ticker naming the fingerprints the tool computes. The theme is deliberately plain: a black ground, bone text, one hot accent, and mono for anything that is data, because the values are the point and everything else is furniture.

**Overview** is the first thing the console shows and answers whether there is anything here at all. Four counter tiles report the events observed, the alerts raised, the fingerprints held and the intel records loaded. Below them a severity breakdown draws one bar per severity that has fired, scaled to the largest, so the shape of the alert load is visible before any filter is applied; and a fingerprint-kind distribution draws one bar per fingerprint kind, weighted by how often each has been seen. An empty console says so in words rather than drawing empty bars.

**Live** is the view that makes this a console rather than a report. It shows the capture state — interface, packets, packets per second, flows, events and alerts — beside a start/stop button, an interface picker and a filter box, and under it a stream of handshakes arriving as they are fingerprinted. Each row carries the time, whether it is an event or an alert, the endpoints, the SNI and the fingerprints computed for that flow. A QUIC row is badged with its transport and QUIC version, and a row whose ClientHello offered ECH is badged so that its value is not read as an identifier when it may be a decoy. The stream is server-sent events, so rows appear without polling and the feed holds the most recent rows rather than growing without bound.

**Alerts** is the queue. A rule dropdown and a severity dropdown narrow the table, and the rule list is filled from the rules that have actually fired rather than from a fixed list. Each row carries a severity chip, the rule, the title, the detail that says why the rule fired, the source address and the fingerprint involved. The detail is the point of the view: an alert names the value that matched, so a reader can disagree with a specific rule instead of arguing with a verdict.

**Fingerprints** is the inventory of everything the store has seen, independent of whether it alerted. A text box filters by kind or value, and the table lists each fingerprint's kind, value, how many times it has been observed, and when it was first and last seen. This is where a first_seen alert's subject can be checked against everything else that arrived with it.

**Intel** is the reference set, made searchable. A text box matches against the value or the name, and a row of chips filters by fingerprint kind; the chips are built from the corpus itself, so they reflect what is loaded rather than a fixed list. The table shows the value, the name, the category, the source and the licence for every matching record, which is what lets a known_bad alert be traced back to the feed it came from. A note line reports how many records matched and whether the result was capped.

**Scope** states plainly what the console is looking at. It prints the capture mode, the interface and the capture file — all empty in the default configuration — and the app's scope note, which in the default configuration describes the file-and-ingest path: the console reads a capture file or events posted to its API, and it never transmits traffic. Live capture runs from the `watch` command rather than through this view, and `watch` prints the interface and the filter it is using on the command line. It is the view that keeps the tool's boundaries in front of the operator.

**Export** writes the current events and alerts out as a single file, in JSON for a complete record or CSV for a spreadsheet, as a download. The view notes that an export reflects the store at the moment of the click.

The top bar carries a health pill that reads `ok` or `unreachable`, the interface currently under capture and a UTC clock, so the state of the deck is visible from every view. The masthead repeats the four Overview counters and carries the **ingest sample** button, which posts a pair of synthetic events to the API — the quickest way to watch a first_seen or a known_bad alert appear on a running console.

## API routes

The console is a thin layer over a JSON API, and every view is built from these routes.

| Route | Method | Purpose |
| --- | --- | --- |
| `/` | GET | The console page. |
| `/api/health` | GET | `{"status": "ok"}` when the app is up. |
| `/api/stats` | GET | Event, alert and fingerprint counts, alerts grouped by rule and by severity, and the intel totals. |
| `/api/alerts` | GET | Alerts newest first; accepts `rule`, `severity` and `limit`. |
| `/api/events` | GET | Events newest first; accepts `sni` (substring) and `limit`. |
| `/api/fingerprints` | GET | The fingerprint inventory with counts and first and last seen times. |
| `/api/intel` | GET | Corpus statistics and a sample of entries. |
| `/api/intel/search` | GET | Search the corpus by value or name; accepts `q` and `kind`; results are capped. |
| `/api/scope` | GET | The configured capture scope: mode, interface, capture file and note. |
| `/api/export` | GET | `format=json` or `format=csv`, returned as a file download. |
| `/api/ingest` | POST | Accept `{"events": [...]}`, run the rules, store the events and alerts, and answer `{"accepted": n, "alerts": n}`. |
| `/api/match` | GET | Identify one fingerprint against the corpus with a confidence and the reasoning; accepts `kind` and `value`. |
| `/api/diversity` | GET | Per-source fingerprint variety and the values shared across sources; accepts `limit`. |

`/api/ingest` is how a capture analysed elsewhere, or a live sensor, feeds the console: it takes events in the same shape the pipeline produces and runs them through the same rules, so the store does not care whether an event came from a file or from the API.

## Tests

```console
python -m pytest -q tests
```

The suite is organised around what each module promises. The JA3 and JA4 tests assert the published worked examples verbatim — the Salesforce JA3 examples, the FoxIO JA4 worked example and its extension-hash variants, and the JA4S, JA4X, JA4T and JA4H examples — along with GREASE handling, the version and ALPN codes and the empty-list cases. The parser tests round-trip hand-built ClientHello, ServerHello and Certificate bytes and check the exact fields they produce. The capture tests cover classic pcap, pcapng, IPv6 and VLAN frames, truncated files and bad magic. The store, corpus, rules and API each have their own tests, and an integration suite drives the real store, corpus and rules through the real `/api/ingest` endpoint to confirm that every rule can actually fire through the app rather than only in isolation. The QUIC tests assert the RFC 9001 Appendix A client Initial vector value by value — the derived keys, the unprotected header, the packet number and the recovered ClientHello — and the matcher tests pin the confidence scores, including the JA3 miss that is meant to return none.
