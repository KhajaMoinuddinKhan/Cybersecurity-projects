# Cybersecurity projects

A collection of Python projects about the same journey: taking a raw piece of security data and turning it into something a person can act on. One project answers whether a file changed. Another collects live Windows events, classifies them, stores them, and puts an analyst view in front of you. Most sit somewhere in between.

Two things hold the set together. The code is meant to be read, and every result is meant to be traceable back to the input that produced it. There are no seeded sample events, no invented findings, and no summary numbers that came from anywhere other than the data you handed over.

Each project is self-contained: its own source, tests, run instructions and learning notes. You can work through one without touching the others, and nothing here depends on a cloud account or an external service.

## The projects

| Project | What it does |
| --- | --- |
| [PCAP Traffic Summary](PROJECTS/pcap-traffic-summary) | Reads a PCAP you supply and prints protocols, top talkers, destination ports and DNS names. |
| [Network Traffic Analyzer](PROJECTS/network-traffic-analyzer) | Streams a PCAP packet by packet for the same summary, with a JSON output mode. |
| [Phishing URL Detector](PROJECTS/phishing-url-detector) | Scores URLs against a few explainable phishing clues and shows its reasoning. |
| [File Integrity Monitor](PROJECTS/file-integrity-monitor) | Baselines a folder with SHA-256 and reports files that were added, changed or removed. |
| [Keylogger](PROJECTS/keylogger) | Records visible, consent-based keystrokes from your own terminal into a local JSONL file. |
| [Hash Cracker](PROJECTS/hash-cracker) | Tests an offline digest against a wordlist you provide and reports the measured work. |
| [SIEM Dashboard](PROJECTS/siem-dashboard) | Collects Windows Event Logs, applies event-based rules, stores telemetry in SQLite and serves a live dashboard. |
| [Threat Intelligence Aggregator](PROJECTS/threat-intelligence-aggregator) | Imports IP, domain, hash and URL indicators from CSV or JSON into a searchable SQLite database. |
| [SSL/TLS Scanner](PROJECTS/ssl-tls-scanner) | Reports the protocol, cipher, certificate identity and expiry from one verified handshake. |
| [Password Policy Auditor](PROJECTS/password-policy-auditor) | Compares a password policy file against an explicit baseline, one setting per line. |
| [Docker Security Audit](PROJECTS/docker-security-audit) | Reviews saved `docker inspect` data for privileged mode, host namespaces, sensitive mounts and published ports. |
| [Web Vulnerability Scanner](PROJECTS/web-vulnerability-scanner) | Runs passive checks against a localhost page for missing security headers and risky form settings. |
| [Cloud Asset Inventory](PROJECTS/cloud-asset-inventory) | Flags public assets, missing ownership tags and unrecorded regions in a JSON inventory export. |

## Getting started

Python 3.10 or newer. Each project is self-contained, so you install its dependencies and run it from inside its own directory:

```console
cd PROJECTS/password-policy-auditor
python -m pip install -r requirements.txt
python -m src.audit sample_policy.conf
```

Four projects need third-party packages: the two packet tools use Scapy, the SIEM dashboard uses Flask and psutil, and the web scanner uses requests. The remaining projects use the standard library alone, and a few of them ship a `requirements.txt` that is deliberately empty to make that explicit.

To run every test suite in one go, install the runner and those four dependency files, then use the repository runner:

```console
python -m pip install pytest
python -m pip install -r PROJECTS/pcap-traffic-summary/requirements.txt
python -m pip install -r PROJECTS/network-traffic-analyzer/requirements.txt
python -m pip install -r PROJECTS/siem-dashboard/requirements.txt
python -m pip install -r PROJECTS/web-vulnerability-scanner/requirements.txt
python scripts/check_all.py
```

## Where to go next

- [Project catalog](PROJECT_CATALOG.md) groups the projects by the kind of input you have in front of you.
- [Running and interpreting the checks](TESTING.md) explains what a green run does and does not establish.
- Each project carries a `learn/` folder with notes on the concepts, the architecture, and the problems that came up while building it.
