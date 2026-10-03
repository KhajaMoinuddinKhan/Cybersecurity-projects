# Cybersecurity projects

A collection of Python projects about the same journey: taking a raw piece of security data and turning it into something a person can act on. One project answers whether a file changed. Another collects live Windows events, classifies them, stores them, and puts an analyst view in front of you. Most sit somewhere in between.

Two things hold the set together. The code is meant to be read, and every result is meant to be traceable back to the input that produced it. There are no seeded sample events, no invented findings, and no summary numbers that came from anywhere other than the data you handed over.

Each project is self-contained: its own source, tests, run instructions and learning notes. You can work through one without touching the others, and nothing here depends on a cloud account or an external service.

## The projects

Listed largest first.

| Project | What it does |
| --- | --- |
| [SIEM Dashboard](PROJECTS/siem-dashboard) | Collects Windows Event Log and Sysmon telemetry from agents on many machines, normalises it to one event schema, classifies and correlates it with rules loaded from files, and gives analysts a triage queue, indexed search, per-host baselining, accounts with roles and multi-factor sign-in, and verified backups. |
| [Threat Intelligence Aggregator](PROJECTS/threat-intelligence-aggregator) | Merges indicators from several feeds and URLs into one store, normalising by type, tracking which sources reported each one, scoring confidence and expiring stale entries. |
| [SSL/TLS Scanner](PROJECTS/ssl-tls-scanner) | Enumerates the protocol versions a server accepts, flags weak cipher families, reads the whole certificate chain, checks hostname match, expiry and HSTS, and grades the result. |
| [Web Vulnerability Scanner](PROJECTS/web-vulnerability-scanner) | Probes a localhost page for reflected input, error-based SQL injection, open redirects, cookie flags, dangerous HTTP methods, exposed paths and missing anti-CSRF tokens, alongside the security-header checks. |
| [Cloud Asset Inventory](PROJECTS/cloud-asset-inventory) | Normalises AWS Config, Azure Resource Graph and GCP asset exports into one inventory, then flags public exposure, unencrypted storage and missing tags, owner or region. |
| [Docker Security Audit](PROJECTS/docker-security-audit) | Audits saved `docker inspect` data against a CIS-style checklist: privileges, host namespaces, capabilities, seccomp and AppArmor, sensitive mounts, published ports, image pinning, resource limits and secrets in the environment. |
| [Phishing URL Detector](PROJECTS/phishing-url-detector) | Scores URLs against explainable signals - lookalike and punycode hosts, typosquatting, abused top-level domains, encoded paths, credential words - and can explain every signal that did and did not fire. |
| [Password Policy Auditor](PROJECTS/password-policy-auditor) | Scores a policy file against NIST SP 800-63B, CIS or PCI-DSS profiles, and audits a list of candidate passwords against the effective policy with the reason each one fails. |
| [Network Traffic Analyzer](PROJECTS/network-traffic-analyzer) | Streams a capture packet by packet with byte and flow accounting, the time range and rates, host, port and protocol filters, and a JSON output mode. |
| [File Integrity Monitor](PROJECTS/file-integrity-monitor) | Baselines a folder with SHA-256 plus size, modification time and permissions, then reports added, changed, removed and permission-only changes, with a watch mode, exclude patterns and JSON output. |
| [PCAP Traffic Summary](PROJECTS/pcap-traffic-summary) | Reads a PCAP you supply and reports protocols, byte totals, top talkers, five-tuple flows, destination ports and DNS names, with the capture time range and the rates derived from it. |
| [Hash Cracker](PROJECTS/hash-cracker) | Tests digests against a wordlist with automatic algorithm detection, salts, mangling rules and a bounded brute-force mode, reporting the measured work. |
| [Consent-based terminal key recorder](PROJECTS/keylogger) | Records visible keystrokes from the terminal that launched it into a local JSONL file, behind an explicit consent flag, with no background hook. |
