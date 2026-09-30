# Cybersecurity projects

A collection of practical cybersecurity projects built mainly in Python. The projects cover network analysis, detection, monitoring, security checks, and configuration review.

| Project | What it does |
| --- | --- |
| [Network Traffic Analyzer](PROJECTS/beginner/01-network-traffic-analyzer) | Reads PCAP files and summarizes protocols, source hosts, destination ports, and DNS queries. |
| [Phishing URL Detector](PROJECTS/beginner/02-phishing-url-detector) | Scores URLs with simple phishing clues and explains why a URL received its score. |
| [File Integrity Monitor](PROJECTS/beginner/03-file-integrity-monitor) | Creates SHA-256 baselines and reports files that were added, changed, or removed. |
| [SIEM Dashboard](PROJECTS/intermediate/04-siem-dashboard) | Stores synthetic security events in SQLite and displays them in a local Flask dashboard with search and severity filters. |
| [Threat Intelligence Aggregator](PROJECTS/intermediate/05-threat-intelligence-aggregator) | Imports IP, domain, hash, and URL indicators from CSV or JSON into a searchable SQLite database. |
| [SSL/TLS Scanner](PROJECTS/intermediate/06-ssl-tls-scanner) | Connects to a TLS endpoint and reports the negotiated protocol, cipher, certificate subject, issuer, and expiry. |
| [Password Policy Auditor](PROJECTS/intermediate/07-password-policy-auditor) | Reads a simple policy file and compares password settings with a visible baseline. |
| [Docker Security Audit](PROJECTS/intermediate/08-docker-security-audit) | Reviews Docker inspect data for risky settings such as privileged mode, host namespaces, sensitive mounts, and published ports. |
| [Web Vulnerability Scanner](PROJECTS/moderate/09-web-vulnerability-scanner) | Runs passive checks against localhost pages for missing security headers and risky form settings. |
| [Cloud Asset Inventory](PROJECTS/moderate/10-cloud-asset-inventory) | Reads a synthetic cloud inventory and flags public assets, missing tags, malformed metadata, and missing regions. |
