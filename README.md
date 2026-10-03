# Cybersecurity projects

A collection of Python projects about the same journey: taking a raw piece of security data and turning it into something a person can act on. One project answers whether a file changed. Another collects live Windows events, classifies them, stores them, and puts an analyst view in front of you. Most sit somewhere in between.

Two things hold the set together. The code is meant to be read, and every result is meant to be traceable back to the input that produced it. There are no seeded sample events, no invented findings, and no summary numbers that came from anywhere other than the data you handed over.

Each project is self-contained: its own source, tests, run instructions and learning notes. You can work through one without touching the others, and nothing here depends on a cloud account or an external service.

## The projects

Listed largest first.

| Project | What it does |
| --- | --- |
| [SIEM Dashboard](PROJECTS/siem-dashboard) | Collects Windows Event Log and Sysmon telemetry, classifies it with rules loaded from files, correlates sequences across sources, and serves a live dashboard. |
| [PCAP Traffic Summary](PROJECTS/pcap-traffic-summary) | Reads a PCAP you supply and prints protocols, top talkers, destination ports and DNS names. |
| [Network Traffic Analyzer](PROJECTS/network-traffic-analyzer) | Streams a PCAP packet by packet for the same summary, with a JSON output mode. |
| [Consent-based terminal key recorder](PROJECTS/keylogger) | Records visible keystrokes from the terminal that launched it into a local JSONL file, behind an explicit consent flag, with no background hook. |
| [File Integrity Monitor](PROJECTS/file-integrity-monitor) | Baselines a folder with SHA-256 and reports files that were added, changed or removed. |
| [Web Vulnerability Scanner](PROJECTS/web-vulnerability-scanner) | Runs passive checks against a localhost page for missing security headers and risky form settings. |
| [Threat Intelligence Aggregator](PROJECTS/threat-intelligence-aggregator) | Imports IP, domain, hash and URL indicators from CSV or JSON into a searchable SQLite database. |
| [Docker Security Audit](PROJECTS/docker-security-audit) | Reviews saved `docker inspect` data for privileged mode, host namespaces, sensitive mounts and published ports. |
| [SSL/TLS Scanner](PROJECTS/ssl-tls-scanner) | Reports the protocol, cipher, certificate identity and expiry from one verified handshake. |
| [Password Policy Auditor](PROJECTS/password-policy-auditor) | Compares a password policy file against an explicit baseline, one setting per line. |
| [Cloud Asset Inventory](PROJECTS/cloud-asset-inventory) | Flags public assets, missing ownership tags and unrecorded regions in a JSON inventory export. |
| [Phishing URL Detector](PROJECTS/phishing-url-detector) | Scores URLs against a few explainable phishing clues and shows its reasoning. |
| [Hash Cracker](PROJECTS/hash-cracker) | Tests an offline digest against a wordlist you provide and reports the measured work. |
