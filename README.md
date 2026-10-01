# Cybersecurity projects

This repository brings together eleven Python projects for learning how security data moves from a raw input to an explanation someone can act on. Some tools answer a small question, such as whether a file changed. Others combine collection, storage, detection, and an analyst interface.

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
| [Purple Team Detection Lab](PROJECTS/advanced/11-purple-team-detection-lab) | Correlates security events into ATT&CK-mapped alerts and includes a passive public-website security check in the analyst dashboard. |

For a first run without network access, try the URL detector, file monitor, or one of the supplied configuration-review fixtures. For real Windows telemetry, use the SIEM. For correlation rules and repeatable investigation exercises, use the Purple Team Detection Lab. The [project catalog](PROJECT_CATALOG.md) groups the tools by their inputs and learning goals.

## Get started in VS Code

Install Python 3.12 or 3.13 and Git, then open the repository folder in VS Code. In a new terminal, create an isolated environment:

```powershell
git clone https://github.com/KhajaMoinuddinKhan/Cybersecurity-projects.git
cd Cybersecurity-projects
python -m venv .venv
```

In VS Code, run **Python: Select Interpreter** and choose the Python executable inside `.venv`. On Windows you can use it directly, even if PowerShell does not allow activation scripts:

```powershell
.\.venv\Scripts\python.exe -m pip install pytest
cd PROJECTS\intermediate\04-siem-dashboard
..\..\..\.venv\Scripts\python.exe -m pip install -r requirements.txt
..\..\..\.venv\Scripts\python.exe -m src.app
```

Open `http://127.0.0.1:5000` for the SIEM. Stop the application with Ctrl+C. To use the shorter `python` commands in the project guides, activate the environment from the repository root with `.\.venv\Scripts\Activate.ps1`. On macOS or Linux, use `source .venv/bin/activate`.

For another project, change into its directory and follow its README. Install its `requirements.txt` if it has one. Projects without dependencies use the standard library. Run module commands such as `python -m src.audit` from the project directory; running them from the repository root will not find that project's `src` package.

## Update an existing checkout

From the repository folder, run `git status` to check your local changes, then `git pull origin main`. If Git says that `origin` does not exist, inspect the configured remotes with `git remote -v`. In an existing checkout of this repository that has no origin, add it:

```powershell
git remote add origin https://github.com/KhajaMoinuddinKhan/Cybersecurity-projects.git
git pull origin main
```

If the folder is not a Git checkout, clone into a new folder instead of replacing your existing work. If Git reports conflicts or unrelated histories, keep your local files and resolve the mismatch before pulling again.

## Run the checks

Install the chosen project's dependencies and pytest, then run:

```console
python -m compileall -q src
python -m pytest -q tests
```

Each project uses the package name `src`, so run its tests from its own directory. To check the whole repository in separate Python processes, use `python scripts/check_all.py` from the root after installing the dependencies listed in [TESTING.md](TESTING.md). GitHub Actions runs all eleven projects on Linux and the SIEM on Windows. Node.js is needed for the SIEM's JavaScript control test.

## Where the data comes from

The SIEM collects actual Windows Event Logs and accepts files or API records you supply. Its normal database is not seeded with sample events. Access to the Security log depends on Windows permissions; the [SIEM guide](PROJECTS/intermediate/04-siem-dashboard/README.md) explains the permission error and collector status.

The configuration tools and Purple Team event lab include clearly labeled training fixtures so their behavior can be reproduced. Those files are examples, not observations from your computer or cloud account. The TLS scanner and Purple Team website check make real network requests when you explicitly run them. The local web checker stays on localhost.

## Reading and extending the code

A project README gives you the working path from setup to interpreting a result. Its `learn/` directory covers concepts, architecture, implementation details, and limitations. Start with a small input whose expected result you understand, change one condition, and compare the output. When adding a rule, keep the explanation close to the condition and add a test for both the matching case and an important non-matching case.

These are focused learning tools. Their reports help you investigate; a clean report only means the implemented checks did not find a match. The dashboards bind to localhost by default and are intended for a trusted local environment.
