# Running and interpreting the checks

Tests should make changes easier to trust, but their result only applies to the behavior they exercise. This repository separates repeatable fixture tests from native operating-system and external-network checks.

## Check the whole repository

Create and activate a virtual environment as described in the root README. Install the test runner and the dependencies used across the projects:

```console
python -m pip install pytest
python -m pip install -r PROJECTS/beginner/01-network-traffic-analyzer/requirements.txt
python -m pip install -r PROJECTS/intermediate/04-siem-dashboard/requirements.txt
python -m pip install -r PROJECTS/moderate/09-web-vulnerability-scanner/requirements.txt
python scripts/check_all.py
```

Install Node.js as well to run the SIEM JavaScript control check. The other projects use the standard library. The runner compiles each source directory, launches its tests in a separate Python process, continues through the remaining projects after a failure, and returns a nonzero exit status if anything fails. Separate processes are necessary because the projects deliberately reuse the package name `src`.

To focus on one project, change into its directory and run `python -m pytest -q tests`. For more context on a failure, replace `-q` with `-v`.

## What is exercised

| Area | Evidence from tests |
| --- | --- |
| Packet analysis | Summary counters and a generated PCAP containing a DNS query and reply. |
| URL scoring | Known heuristic outcomes and malformed-input handling. |
| File integrity | Added, modified, and removed files, an internal baseline file, and invalid baseline metadata. |
| Terminal input | Consent enforcement, special-key labels, and JSONL event writing. |
| Offline hash recovery | Real digest comparisons, streamed wordlists, no-match results, and invalid target handling. |
| PCAP analysis | Protocol, endpoint, port, and DNS aggregation over observed packet records. |
| SIEM | Empty startup, classification, deduplication, filters, imports, atomic validation, metrics, collector retry logic, and JavaScript controls against a temporary Flask API. |
| Indicator feeds | Deduplication, literal searches, and invalid field types. |
| TLS | Certificate formatting and session behavior using controlled connection objects. |
| Policy and Docker review | Baseline comparisons, risky settings, explicit root users, structured mounts, multiple containers, and malformed inputs. |
| Local web and inventory review | Localhost boundaries, response/form checks, and inventory metadata findings. |

The SIEM control test runs the shipped JavaScript in a small DOM harness against a real local API. It verifies behavior, but it does not replace a visual browser review. Tests create temporary files and databases; they do not seed the normal SIEM store.

## Platform and network boundaries

The native SIEM test reads actual System events on Windows. It is skipped on other operating systems. The GitHub Actions Windows job runs it alongside the API and control tests. Security-channel access still depends on the account and machine policy, so a passing System-log test does not establish that every channel is accessible on your computer.

Scapy may discover local network interfaces while importing its packet layers. A highly restricted container can block that initialization even though the analyzer only reads a file. Run the capture tests on a normal workstation or the Linux CI runner in that case; do not report an unexecuted capture test as a pass.

External endpoints can change or become unreachable. Automated website boundary tests use controlled DNS and socket behavior, and TLS tests retain certificate-verification behavior without depending on a public site's availability. A live inspection is a separate observation tied to its endpoint and time.

## Before accepting a change

Run the affected project tests, then the full runner when shared instructions, dependencies, or workflows change. Try the documented command with an input you understand and inspect the output, including a failure case. Review GitHub Actions for the pushed commit; local Linux results cannot substitute for the Windows collector job.
