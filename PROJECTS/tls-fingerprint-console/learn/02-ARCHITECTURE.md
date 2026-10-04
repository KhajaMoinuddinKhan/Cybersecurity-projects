# Architecture

1. The command line (`src/cli.py`) dispatches one of five subcommands. `analyse` calls the pipeline over a capture file; `demo` builds a synthetic capture and does the same; `interfaces` and `watch` drive the live path; `serve` builds the Flask app around a store and the corpus.
2. `src/pcap.py` reads the capture into a list of packet dicts — timestamps, endpoints, flags, sequence numbers, TCP options and payload — decoding classic pcap or pcapng, Ethernet II or raw IP, IPv4 or IPv6, TCP or UDP, and following VLAN tags.
3. `reassemble_streams()` groups TCP payloads by direction, orders each direction by sequence number and concatenates it, dropping empty acknowledgements, so each direction is one byte stream.
4. `src/pipeline.py` buckets the streams into bidirectional flows and picks the client as the direction that carried a ClientHello. When no direction did, it tries the streams as plaintext HTTP and stops there if none parses.
5. `src/tls.py` parses the ClientHello into the field lists the fingerprints need, in wire order and still carrying GREASE.
6. `src/ja3.py` and `src/ja4.py` strip GREASE, build their pre-hash strings, and return the JA3 and JA4 values.
7. The server stream yields a ServerHello, parsed for JA3S and JA4S, and a Certificate message, whose first certificate becomes a JA4X.
8. The client's SYN, found among the packets by its flags, is parsed for window, option kinds, MSS and window scale, and becomes a JA4T.
9. A plaintext HTTP request on the client stream is parsed for method, version, headers, cookie, referer and language, and becomes a JA4H.
10. `events_from_pcap()` assembles one event per flow and, when a corpus is supplied, attaches the category and name of any fingerprint it matches.
11. `analyse()` builds a context holding the store, the corpus, the store's `seen_before` and an OS map derived from the corpus, evaluates the rules over each event, and only then writes the event and its alerts to the store.
12. `src/store.py` keeps three SQLite tables: one row per event, one per alert, and one row per distinct fingerprint value with its first-seen time, last-seen time and count.
13. `src/app.py` serves the stored data as JSON and renders the single console page; `src/templates/console.html` polls those endpoints and draws the six views.
14. The live path begins in `src/capture.py`. It lists the capturable interfaces with their descriptions, picks one by index or by a substring of its description, opens it with a snapshot length and promiscuous mode, compiles and installs a BPF filter, and reads frames from the driver. Each frame is decoded through the same `decode_frame` that `src/pcap.py` uses on a capture file, so a live packet and a recorded one arrive downstream as the same dict.
15. `src/live.py` holds a table of in-flight flows keyed by the sorted endpoint pair. As each packet arrives it appends the payload to that direction's buffer, then tries, in turn, to read a ClientHello, a ServerHello, a Certificate and a plaintext HTTP request out of whatever has accumulated, storing each fingerprint it can compute. It runs on the packet clock — the largest timestamp it has seen — rather than the wall clock.
16. When a flow goes quiet — the server has answered and the flow has been idle for the grace period, or a hard cap has passed — the sensor emits one event in exactly the shape `events_from_pcap()` produces and runs the same rules over it, so a live event and a file event are indistinguishable to the store, the rules and the console.

The modules are deliberately separated by what they know. `pcap.py` knows about packets and nothing about TLS. `tls.py` knows about TLS bytes and nothing about fingerprints. `ja3.py` and `ja4.py` know about hashing field lists and nothing about where the lists came from. `rules.py` knows about events and the context around them and nothing about captures. `store.py` knows about persistence and nothing about meaning. The pipeline is the only module that has to know the shape of all of them, which is why it is the only module that reads like glue.

The corpus is injected rather than imported by the modules that use it, and so are the store and the rules module. That is what lets the whole thing be tested with in-memory stand-ins that implement the same interface, and it is why the app can be built before every sibling module exists: `create_app()` resolves the rules module lazily and falls back to a no-op evaluator when it cannot be imported.

The live and file paths are two front doors onto the same machinery. `src/capture.py` decodes every captured frame with the decoder in `src/pcap.py`, and `src/live.py` parses and fingerprints with the same `parse_client_hello`, `parse_server_hello`, `parse_certificate_message`, `parse_http_request`, `ja3` and `ja4` functions the pipeline calls. Nothing about a fingerprint depends on where the bytes came from, so the only thing the live path decides for itself is when a flow is finished: it cannot wait for a whole capture, so it reads that answer from the packets' own clock as they arrive.

[Back to the project guide](../README.md)
