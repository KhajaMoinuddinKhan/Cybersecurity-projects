# Running and interpreting the checks

A test result is only as broad as the behaviour it exercises, and it is easy to read more into a green run than it says. This repository splits its checks into the repeatable ones that run anywhere and the ones that depend on your operating system or a live endpoint.

## Running everything

Create and activate a virtual environment as described in the root README, then install the test runner and the dependencies for the four projects that need them:

```console
python -m pip install pytest
python -m pip install -r PROJECTS/pcap-traffic-summary/requirements.txt
python -m pip install -r PROJECTS/network-traffic-analyzer/requirements.txt
python -m pip install -r PROJECTS/siem-dashboard/requirements.txt
python -m pip install -r PROJECTS/web-vulnerability-scanner/requirements.txt
python scripts/check_all.py
```

The runner compiles each project's source and runs its tests in a separate Python process, keeps going after a failure, and exits nonzero if anything failed. Separate processes are not a style choice: every project deliberately uses the package name `src`, so collecting them in one interpreter would be ambiguous.

To work on a single project, `cd` into it and run `python -m pytest -q tests`. Swap `-q` for `-v` when you want to see each test name.

Node.js is needed for one extra check: the SIEM JavaScript controls are exercised in a small DOM harness against a temporary API. Everything else is Python and the standard library.

## What the automated checks actually cover

| Area | Evidence from the tests |
| --- | --- |
| Packet analysis | Summary counters, generated captures, a DNS query and reply, truncated frames, ICMP errors quoting a DNS query, and packets asking several questions. |
| URL scoring | Known heuristic outcomes, malformed input, scheme-less and protocol-relative URLs. |
| File integrity | Added, modified and removed files, a baseline stored inside the watched folder, invalid metadata, byte-order marks, upper-case digests. |
| Terminal input | Consent enforcement, key labelling, JSONL writing, refusal when stdin is not a console, Ctrl+C handling. |
| Offline hash recovery | Real digest comparisons, streamed wordlists, no-match results, invalid targets and unsupported algorithms. |
| SIEM | Empty startup, event classification, deduplication, filters, JSON/JSONL/CSV import, atomic validation, metrics, collector retry logic, and the JavaScript controls. |
| Indicator feeds | Normalisation, deduplication counts, literal search, and every malformed-input path. |
| TLS | Certificate formatting, session behaviour with controlled sockets, and the port and timeout bounds. |
| Policy, Docker, inventory and web review | Baseline comparisons, risky container settings, localhost boundaries, response and form checks, metadata findings. |

Tests create their own temporary files and databases. They do not seed the SIEM store you use day to day, and they never reach an external host.

## Where a green run stops being evidence

**Operating system.** The native SIEM test reads real System events on Windows and is skipped elsewhere. The GitHub Actions Windows job runs it alongside the API and control tests. Access to the Security channel depends on the account and the machine policy, so a passing System-log test does not establish that every channel is readable on your computer.

**Scapy's import time.** Scapy may probe local network interfaces while importing its packet layers. A tightly restricted container can block that even though the analyzers only read a file. If the capture tests cannot start there, run them on a normal workstation or on the Linux CI runner — and do not record an unexecuted capture test as a pass.

**External endpoints.** Sites change and go offline. The tests therefore use controlled sockets and temporary local servers rather than a public website, so a passing suite says nothing about any particular server on the internet. A live scan is an observation tied to one endpoint and one moment.

## Before accepting a change

Run the tests for the project you touched, then the full runner if you changed shared instructions, dependencies or workflows. Run the documented command yourself with an input you understand, and try a failing case as well as a successful one — most of the defects found in this repository were in paths the tests were perfectly happy with. Finally, check the GitHub Actions result for the pushed commit; a local Linux run cannot stand in for the Windows collector job.
