# Project catalog

Choose a project by the data you already have and the question you want to answer. The level labels describe the repository's learning progression, not a certification or a guarantee of production readiness.

## Start with one input and one result

| Project | Bring this input | What to learn |
| --- | --- | --- |
| [Network Traffic Analyzer](PROJECTS/beginner/01-network-traffic-analyzer) | A PCAP from your lab | Extract packet fields and turn them into an interpretable summary. |
| [Phishing URL Detector](PROJECTS/beginner/02-phishing-url-detector) | One or more URL strings | Keep heuristic scores explainable and distinguish clues from verdicts. |
| [File Integrity Monitor](PROJECTS/beginner/03-file-integrity-monitor) | A folder and a trusted baseline | Compare content hashes and separate added, changed, and removed files. |
| [Keylogger](PROJECTS/beginner/keylogger) | Your authorized foreground terminal | Learn visible consent, terminal input, and safe local event recording. |
| [Network Traffic Analyzer](PROJECTS/beginner/network-traffic-analyzer) | A PCAP from your lab | Stream packet observations into a compact, input-driven report. |
| [Hash Cracker](PROJECTS/beginner/hash-cracker) | An authorized digest and wordlist | Compare offline candidates while measuring actual work. |

The URL detector is a quick offline starting point. The file monitor adds persistence and repeatable comparisons. The packet analyzer introduces protocol parsing and the limits of what a capture can reveal.

## Add storage and configuration context

| Project | Bring this input | What to learn |
| --- | --- | --- |
| [SIEM Dashboard](PROJECTS/intermediate/04-siem-dashboard) | Windows Event Logs, or structured event files/API records | Connect collection, validation, persistence, detection, and live investigation controls. |
| [Threat Intelligence Aggregator](PROJECTS/intermediate/05-threat-intelligence-aggregator) | CSV or JSON indicator feeds | Normalize records, deduplicate with SQLite, and search safely. |
| [SSL/TLS Scanner](PROJECTS/intermediate/06-ssl-tls-scanner) | A hostname and TLS port | Read a verified handshake without confusing one negotiated session with a complete server audit. |
| [Password Policy Auditor](PROJECTS/intermediate/07-password-policy-auditor) | A key=value policy file | Apply field-specific comparisons against an explicit example baseline. |
| [Docker Security Audit](PROJECTS/intermediate/08-docker-security-audit) | Saved docker inspect JSON | Explain container configuration findings and review every object in an export. |

The supplied feed and configuration files are training fixtures. The SIEM instead starts with an empty store and collects actual available events; it can legitimately show zero matching alerts.

## Review applications and inventories

| Project | Bring this input | What to learn |
| --- | --- | --- |
| [Web Vulnerability Scanner](PROJECTS/moderate/09-web-vulnerability-scanner) | A running localhost HTTP application | Inspect response headers and form metadata without submitting data. |
| [Cloud Asset Inventory](PROJECTS/moderate/10-cloud-asset-inventory) | JSON assets mapped to the project schema | Connect exposure and missing metadata to individual resources. |

The local web checker does not crawl or exploit an application. The inventory tool does not connect to a cloud account. Both are deliberately small enough that you can trace every finding to a specific input field.

## Before running a project

Follow the project's README from its own directory. Keep test fixtures separate from collected evidence, and keep a copy of inputs you need for comparison. The root README covers the repository layout and project links; [TESTING.md](TESTING.md) explains the automated checks and their boundaries.
