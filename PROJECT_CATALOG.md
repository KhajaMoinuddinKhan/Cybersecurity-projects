# Project catalog

The projects, grouped by what you have to bring, largest group first and largest project first within each group. Pick the row that matches the data in front of you; the last column is what that project is really teaching.

Two of the rows are flagships rather than tools. The [SIEM Dashboard](PROJECTS/siem-dashboard) and the [MKMK TLS Fingerprint Console](PROJECTS/tls-fingerprint-console) are several times larger than everything else here, and they are the two that go past doing a job correctly into owning a whole pipeline: collection, validation, storage, detection and a workflow on top. They appear in their groups below like any other row, but they are the two worth reading first if you want to see where the set is heading.

## You have a live system or a service

| Project | Bring this | What you will practise |
| --- | --- | --- |
| [SIEM Dashboard](PROJECTS/siem-dashboard) | Windows Event Logs and Sysmon from one or more machines, a packet capture, or structured event files and API records | Connecting collection, validation, storage, detection, correlation, multi-host ingestion, baselining and an analyst workflow. |
| [SSL/TLS Scanner](PROJECTS/ssl-tls-scanner) | A hostname and a TLS port | Enumerating what a server will actually negotiate, and deriving a grade only from the checks that were performed. |
| [Web Vulnerability Scanner](PROJECTS/web-vulnerability-scanner) | A web application running on localhost | Submitting benign probes safely, and why a suspected finding is not a confirmed one. |
| [Consent-based terminal key recorder](PROJECTS/keylogger) | Your own foreground terminal | Consent, visible recording, and what keyboard events actually look like. |

The SIEM is the only project that watches a running machine. It starts from an empty store and collects what is genuinely available, so an empty dashboard is a real result, not a broken one. The TLS and web tools each make a single connection to a target you name, and neither will point anywhere but a local address for the web checker.

## You have configuration or an export

| Project | Bring this | What you will practise |
| --- | --- | --- |
| [Threat Intelligence Aggregator](PROJECTS/threat-intelligence-aggregator) | CSV or JSON indicator feeds | Normalising records by type, merging one indicator across feeds, and ageing what you keep. |
| [Cloud Asset Inventory](PROJECTS/cloud-asset-inventory) | An export from AWS, Azure or GCP | Adapting several providers' export shapes into one asset model, and linking exposure to individual resources. |
| [Docker Security Audit](PROJECTS/docker-security-audit) | Saved `docker inspect` JSON | Reading a container's declared configuration against a checklist, and citing the control each finding breaks. |
| [Password Policy Auditor](PROJECTS/password-policy-auditor) | A key=value policy file | Why the standards disagree about composition and expiry, and what a failing password actually fails. |

The bundled `sample_*` files are fixtures, not evidence. They exist so you can see the output shape on the first run; replace them with your own data as soon as you want the results to mean something.

## You have a file

| Project | Bring this | What you will practise |
| --- | --- | --- |
| [Phishing URL Detector](PROJECTS/phishing-url-detector) | One or more URL strings | Keeping a heuristic score explainable, and separating clues from verdicts. |
| [Network Traffic Analyzer](PROJECTS/network-traffic-analyzer) | The same kind of PCAP, possibly a large one | Streaming instead of loading, accounting in bytes and flows, and filtering a report without losing the totals. |
| [File Integrity Monitor](PROJECTS/file-integrity-monitor) | A folder and a trusted baseline | Hashing contents and telling added, changed and removed files apart, and why a permission change is its own kind of change. |
| [MKMK TLS Fingerprint Console](PROJECTS/tls-fingerprint-console) | A capture containing TLS or QUIC/HTTP-3 handshakes, or a network interface to watch live | Reading a handshake field by field, and why a fingerprint is only ever as good as the intel it is matched against. |
| [PCAP Traffic Summary](PROJECTS/pcap-traffic-summary) | A PCAP from your lab | Pulling fields out of packets and turning them into a summary someone can read. |
| [Hash Cracker](PROJECTS/hash-cracker) | A digest you are authorised to test, and a wordlist | Comparing candidates offline and measuring the actual work involved. |

The two traffic tools answer the same question in different ways. The summary tool loads the capture and prints a text report; the analyzer reads it one packet at a time and can print JSON. Start with whichever matches the size of your file and the shape of output you want.

The fingerprint console is the third way into the same traffic, and the only one that reads the encrypted handshake rather than the plaintext around it. It never decrypts the session: what it fingerprints is the negotiation itself, which is sent in the clear before any key exists. QUIC is the one exception worth naming — an HTTP/3 handshake arrives inside an encrypted Initial packet, but that packet's keys come from a public salt and the connection ID, so the console can read it too and fingerprint HTTP/3 alongside TLS. It is also the only project here whose findings depend on someone else's data, so it names the source and licence of every intel record it matches against. It reads a capture file or watches a live interface, and either way the same fingerprints come out, because both paths share one decoder and one set of fingerprint functions.

## You have nothing to hand it

| Project | Bring this | What you will practise |
| --- | --- | --- |
| [Cryptographic toolkit and attack lab](PROJECTS/crypto-toolkit) | Nothing at all | Reading a specification closely enough to reproduce its own worked examples, and why a primitive tested against its own output is being asked to mark its own homework. Then what happens when the same construction is used slightly wrongly, which is the half that makes the rules memorable. |

This is the one project here that is a library rather than a tool, so it is the one that needs no data. It is also the one that is unfinished: the primitives are complete and checked against the published vectors, four attacks run against those same constructions, and RSA, key exchange and the post-quantum benchmark are still to be written. The README names each of those gaps.

## Before running anything

Follow the project's own README from inside its folder. Keep your fixtures separate from anything you are collecting for real, and keep a copy of the inputs you need to compare later. [TESTING.md](TESTING.md) explains the automated checks and where their authority stops; the [root README](README.md) covers the layout.
