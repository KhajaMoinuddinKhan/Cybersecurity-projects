# Cybersecurity projects

Thirteen small Python projects about the same journey: taking a raw piece of security data and turning it into something a person can act on. One project answers whether a file changed. Another collects live Windows events, classifies them, stores them, and puts an analyst view in front of you. Most sit somewhere in between.

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

Clone the repository, then work from inside the project you want to run:

```console
git clone https://github.com/KhajaMoinuddinKhan/Cybersecurity-projects.git
cd Cybersecurity-projects/PROJECTS/phishing-url-detector
python -m src.detector "https://example.com/about"
```

Most projects use nothing but the standard library. Three need a package: Scapy for the two traffic analyzers, Flask and psutil for the SIEM, and requests for the local web checker. Each of those has a `requirements.txt`, and the project README says what to install.

If you would rather not decide, the [project catalog](PROJECT_CATALOG.md) groups the tools by the input you already have, and the URL detector, file monitor and hash cracker are the quickest places to start because they need no network and no setup.

## Repository layout

```
PROJECTS/<project-name>/     one folder per project, side by side
  README.md                  what it does, how to run it, what it will not do
  src/                       the code
  tests/                     pytest suite for that project
  learn/                     background notes on the concepts and tradeoffs
  assets/                    diagrams and screenshots
scripts/check_all.py         compiles and tests every project in its own process
TESTING.md                   what the automated checks cover, and their limits
PROJECT_CATALOG.md           projects grouped by the input they need
```

Every project deliberately uses the package name `src`, which is why the test runner launches each one in a separate process instead of collecting them all at once.

## Before you point any of this at something

The scanners here are narrow on purpose. The web checker only accepts localhost targets, the TLS scanner performs one verified handshake and refuses to disable verification, and the keylogger records only the terminal that launched it, after you pass `--consent`. Keep it that way: use these tools against systems you own or are authorised to test, and read each project's README for the limits of what its output actually means.
