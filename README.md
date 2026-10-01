# Cybersecurity projects

This repository brings together ten Python projects for learning how security data moves from a raw input to an explanation someone can act on. Some tools answer a small question, such as whether a file changed. Others combine collection, storage, detection, and an analyst interface.

The emphasis is on readable code and results you can trace back to the input. Each project has its own source, tests, run instructions, and learning notes. You can work on one project without starting the others.

## Choose a starting point

| Project | What it does |
| --- | --- |
| [Network Traffic Analyzer](PROJECTS/beginner/01-network-traffic-analyzer) | Reads PCAP files and summarizes protocols, source hosts, destination ports, and DNS queries. |
| [Phishing URL Detector](PROJECTS/beginner/02-phishing-url-detector) | Scores URLs with simple phishing clues and explains why a URL received its score. |
| [File Integrity Monitor](PROJECTS/beginner/03-file-integrity-monitor) | Creates SHA-256 baselines and reports files that were added, changed, or removed. |
| [SIEM Dashboard](PROJECTS/intermediate/04-siem-dashboard) | Collects real Windows Event Logs, applies event-based security rules, stores telemetry in SQLite, and updates alerts, filters, timelines, providers, and event triage live. |
| [Threat Intelligence Aggregator](PROJECTS/intermediate/05-threat-intelligence-aggregator) | Imports IP, domain, hash, and URL indicators from CSV or JSON into a searchable SQLite database. |
| [SSL/TLS Scanner](PROJECTS/intermediate/06-ssl-tls-scanner) | Connects to a TLS endpoint and reports the negotiated protocol, cipher, certificate subject, issuer, and expiry. |
| [Password Policy Auditor](PROJECTS/intermediate/07-password-policy-auditor) | Reads a simple policy file and compares password settings with a visible baseline. |
| [Docker Security Audit](PROJECTS/intermediate/08-docker-security-audit) | Reviews Docker inspect data for risky settings such as privileged mode, host namespaces, sensitive mounts, and published ports. |
| [Web Vulnerability Scanner](PROJECTS/moderate/09-web-vulnerability-scanner) | Runs passive checks against localhost pages for missing security headers and risky form settings. |
| [Cloud Asset Inventory](PROJECTS/moderate/10-cloud-asset-inventory) | Reviews a supplied JSON cloud inventory and flags public assets, missing tags, malformed metadata, and missing regions. |

For a first run without network access, try the URL detector, file monitor, or one of the supplied configuration-review fixtures. For real Windows telemetry, use the SIEM. The [project catalog](PROJECT_CATALOG.md) groups the tools by their inputs and learning goals.
