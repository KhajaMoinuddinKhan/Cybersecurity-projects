# Project catalog

The projects, grouped by what you have to bring, largest group first and largest project first within each group. Pick the row that matches the data in front of you; the last column is what that project is really teaching.

## You have a live system or a service

| Project | Bring this | What you will practise |
| --- | --- | --- |
| [SIEM Dashboard](PROJECTS/siem-dashboard) | Windows Event Logs and Sysmon, a packet capture, or structured event files and API records | Connecting collection, validation, storage, detection, correlation and an analyst view. |
| [Consent-based terminal key recorder](PROJECTS/keylogger) | Your own foreground terminal | Consent, visible recording, and what keyboard events actually look like. |
| [Web Vulnerability Scanner](PROJECTS/web-vulnerability-scanner) | A web application running on localhost | Checking response headers and form metadata without submitting anything. |
| [SSL/TLS Scanner](PROJECTS/ssl-tls-scanner) | A hostname and a TLS port | Reading one verified handshake without confusing it for a server audit. |

The SIEM is the only project that watches a running machine. It starts from an empty store and collects what is genuinely available, so an empty dashboard is a real result, not a broken one. The TLS and web tools each make a single connection to a target you name, and neither will point anywhere but a local address for the web checker.

## You have a file

| Project | Bring this | What you will practise |
| --- | --- | --- |
| [PCAP Traffic Summary](PROJECTS/pcap-traffic-summary) | A PCAP from your lab | Pulling fields out of packets and turning them into a summary someone can read. |
| [Network Traffic Analyzer](PROJECTS/network-traffic-analyzer) | The same kind of PCAP, possibly a large one | Streaming instead of loading, and emitting a report another tool can consume. |
| [File Integrity Monitor](PROJECTS/file-integrity-monitor) | A folder and a trusted baseline | Hashing file contents and telling added, changed and removed files apart. |
| [Phishing URL Detector](PROJECTS/phishing-url-detector) | One or more URL strings | Keeping a heuristic score explainable, and separating clues from verdicts. |
| [Hash Cracker](PROJECTS/hash-cracker) | A digest you are authorised to test, and a wordlist | Comparing candidates offline and measuring the actual work involved. |

The two traffic tools answer the same question in different ways. The summary tool loads the capture and prints a text report; the analyzer reads it one packet at a time and can print JSON. Start with whichever matches the size of your file and the shape of output you want.

## You have configuration or an export

| Project | Bring this | What you will practise |
| --- | --- | --- |
| [Threat Intelligence Aggregator](PROJECTS/threat-intelligence-aggregator) | CSV or JSON indicator feeds | Normalising records, deduplicating in SQLite, and searching safely. |
| [Docker Security Audit](PROJECTS/docker-security-audit) | Saved `docker inspect` JSON | Turning container configuration into findings you can defend, one container at a time. |
| [Password Policy Auditor](PROJECTS/password-policy-auditor) | A key=value policy file | Field-by-field comparison against an explicit, reviewable baseline. |
| [Cloud Asset Inventory](PROJECTS/cloud-asset-inventory) | A JSON inventory that matches the project schema | Linking exposure and missing metadata to individual resources. |

The bundled `sample_*` files are fixtures, not evidence. They exist so you can see the output shape on the first run; replace them with your own data as soon as you want the results to mean something.

## Before running anything

Follow the project's own README from inside its folder. Keep your fixtures separate from anything you are collecting for real, and keep a copy of the inputs you need to compare later. [TESTING.md](TESTING.md) explains the automated checks and where their authority stops; the [root README](README.md) covers the layout.
