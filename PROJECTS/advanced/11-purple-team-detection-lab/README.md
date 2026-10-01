# Purple Team Detection Lab

This lab connects raw security events to explainable detections. You can load a repeatable event set, run a small collection of JSON rules, and inspect the resulting alerts in a local dashboard. Each alert retains its rule, mapped ATT&CK technique, time range, and supporting event IDs so the result can be reviewed rather than taken on trust.

The dashboard also includes a separate, on-demand website check. It inspects a public site's HTTP response, security headers, and verified TLS connection. Website findings are separate from the stored event-lab alerts.

## Run the event lab

Use Python 3.12 or 3.13 and open a terminal in this project directory. The application uses the standard library.

```console
python -m src.cli detect
python -m src.cli summary
python -m src.cli serve
```

Open `http://127.0.0.1:8000`. Stop the server with Ctrl+C. Use `--port 8001` if another application already uses 8000.

The default detection run reads `data/sample_events.json` and `rules/detection_rules.json`, then replaces the alerts in `purple_lab.db`. The bundled events are synthetic training fixtures. Running `detect` is an explicit exercise; the server does not continuously collect endpoint events or run the detection engine in the background.

For your own normalized event file or a separate result store:

```console
python -m src.cli detect --events my-events.json --rules rules/detection_rules.json --db investigation.db
python -m src.cli summary --db investigation.db
python -m src.cli serve --db investigation.db
```

Use the same database path in each command. Back up an existing result store before rerunning `detect` if you need to retain its alerts.

## Understand the input

The event file is a JSON list. Each event needs nonempty text fields named `event_id`, `timestamp`, `event_type`, `source`, `user`, and `host`. Event IDs must be unique within the file. Additional rule fields, such as `command_line` or `bytes_out`, belong in the optional `data` object.

Use ISO 8601 timestamps with an offset when possible. The loader converts all times to UTC; a timestamp without an offset is interpreted as UTC. That keeps a mixture of explicit timezones and timezone-free values sortable. Missing fields, malformed timestamps, and duplicate event IDs are rejected before detection starts.

## What the rules look for

| Rule | Trigger | Interpretation |
| --- | --- | --- |
| DET-001 | Five authentication failures from one source within ten minutes | A burst worth investigating for repeated login attempts. |
| DET-002 | A process event containing powershell.exe and an -enc substring | A simple encoded-command clue that still needs command-line review. |
| DET-003 | An outbound connection reporting at least 50,000,000 bytes | A large-transfer threshold, not proof of exfiltration. |
| DET-004 | An added group membership whose group contains admin | A membership change that may be expected administration. |
| DET-005 | An endpoint event reporting a blocked, unsigned script | Evidence of an endpoint control action. |

All conditions in a rule must match. Match rules produce an alert per matching event. Threshold rules group matching events and examine a time window. Once a threshold alert is emitted, its events are consumed for that rule; the next alert requires a new batch rather than repeatedly alerting on the same evidence. The time-window boundary is inclusive.

ATT&CK IDs are mappings written in the rule file. They describe the behavior the rule is intended to investigate; a mapping does not verify that an adversary performed the technique.

## Check a website

Use the website form in the dashboard, or run:

```console
python -m src.cli website https://example.com
```

This makes a real request. The checker starts with HEAD and falls back to GET if the server rejects HEAD with status 405. It inspects response headers without crawling the site or reading a full page body. Public HTTP/HTTPS addresses on ports 80 and 443 are supported. Credential-bearing URLs and non-public IP destinations are rejected, including redirects to private networks. Connections use a validated IP while preserving the original hostname for HTTP and TLS verification.

The result includes status, HTTPS use, header presence, a separately measured TLS session, and findings. The score starts at 100 and subtracts visible rule weights for missing protections; it is a project-specific summary, not an independently validated security rating. Header checks test for nonempty values, not whether the policies are correct. TLS failures are reported rather than bypassed.

The website queue reflects the latest successful check in the browser. It is not saved to the event-alert database and does not refresh continuously. If a later request fails, the error appears while the previous successful queue remains available. Refreshing the page clears that website result.

## Code map

- `src/models.py` defines events, rules, and alerts.
- `src/event_io.py` validates event and rule files.
- `src/engine.py` evaluates conditions and correlates threshold matches.
- `src/storage.py` stores and queries alerts with SQLite.
- `src/dashboard.py` renders the local interface and JSON routes.
- `src/website_check.py` performs passive website checks.
- `src/cli.py` connects these components to the command line.

The [learning notes](learn/00-OVERVIEW.md) walk through the detection pipeline and its boundaries.

## Troubleshooting and scope

An empty event queue can mean you have not run `detect`, you selected a different database, or no rule matched. Check `summary` against the same database before investigating the browser. After rerunning detection, refresh the page to load the updated event alerts.

Website errors can come from DNS, connectivity, TLS trust, unsupported ports, or the public-address restriction. The checker intentionally rejects localhost; use the repository's [local web checker](../../moderate/09-web-vulnerability-scanner) for that workflow.

The server binds to localhost by default and has no authentication. This is a small local lab, not a hosted multi-user service. The event rules cover selected patterns and can produce false positives or miss activity. Keep the original event file for investigation because the alert database stores evidence IDs, not a complete raw-event archive.

## Tests

```console
python -m pip install pytest
python -m pytest -q tests
```

Tests cover matching, correlation, validation, storage, rendering, and website boundary checks. Controlled event fixtures and mocked network behavior make those checks repeatable. They do not demonstrate coverage of every endpoint or public website.
