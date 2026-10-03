# SIEM Dashboard

This is the largest project here, and the only one that watches a live system. It collects Windows Event Log records and Sysmon telemetry, classifies them against rules loaded from files, correlates the results into sequences, stores everything in SQLite, and serves a dashboard you can filter while the data is still arriving.

If you want to see how collection, validation, classification, storage, correlation and an analyst view fit together, start here. If you only want to read a capture file, the traffic tools are a much smaller commitment.

## Running it

```console
python -m pip install -r requirements.txt
python -m src.app
```

That starts the dashboard on `http://127.0.0.1:5000` with a fresh store at `siem_live.db` and begins collecting from the available Windows channels. Useful variations:

```console
python -m src.app --db lab.db --port 5001          # different store and port
python -m src.app --reset                          # clear the live store first
python -m src.app --no-windows-events              # run the API without the collector
python -m src.app --intel-db ../threat-intelligence-aggregator/threat_intel.db
python -m src.app --alert-log alerts.jsonl         # append new alerts as JSON lines
python -m src.app --alert-webhook https://example.invalid/hook
python -m src.app --retain-days 14                 # prune anything older than a fortnight
python -m src.app --auth-token "$SIEM_AUTH_TOKEN"  # require a token on every route
```

`--no-windows-events` is what you want on macOS or Linux, or on a Windows account that cannot read the security channel: the dashboard, the rule engine, the capture import and the filters all work, they simply have no live host source feeding them.

## What you get

The page updates from the current contents of the database, so nothing on it is decorative. Counts, severity breakdowns, events-per-minute, timelines, providers, Event IDs, rule hits, ATT&CK techniques, the correlation panel and the event table are all computed from stored records, and the search, time, channel, provider, Event ID, user, rule, severity and alerts-only filters apply to everything on screen.

## Detection rules are data, not code

Rules live in `src/rules/*.yml`. Editing a detection means editing a file, not this package, and each rule has a stable id so it can be renamed without losing the history of what it fired on.

```yaml
- id: sysmon-encoded-powershell-command
  title: Encoded PowerShell command line
  level: High
  logsource:
    channel: Microsoft-Windows-Sysmon/Operational
    event_id: "1"
  detection:
    selection:
      event_id: "1"
      data.Image|endswith:
        - "\\powershell.exe"
        - "\\pwsh.exe"
    keywords:
      data.CommandLine|contains:
        - "-enc "
        - "-encodedcommand"
    condition: selection and keywords
  tags:
    - attack.execution
    - attack.t1059.001
```

The format follows the Sigma convention closely enough that a Sigma rule is recognisable, but this engine implements a subset rather than all of Sigma. What is supported:

| Feature | Supported |
| --- | --- |
| `logsource` keys `channel`, `event_id`, `provider`, `source` | Applied as an implicit condition |
| Field modifiers | `contains`, `startswith`, `endswith`, `re`, `cidr` |
| List values | Any-of by default; `\|all` requires every value |
| Condition operators | `and`, `or`, `not`, and parentheses |
| Structured event data | Reachable bare (`CommandLine`) or namespaced (`data.CommandLine`) |
| Anything else | Refused at load time with the file and the reason |

A rule that cannot be parsed stops the process rather than being skipped. A detection that silently does not load is worse than one that fails loudly.

Rules are evaluated in severity order, so a `High` rule is never masked by a `Low` one that happened to be checked first. The alert records the rule id, the rule name, the ATT&CK techniques and **which selections matched**, so a reader can see why it fired rather than trusting the verdict.

## Correlation

A single-event rule can say "an encoded PowerShell command ran". It cannot say "and then that same host opened a connection somewhere new". Correlation rules do:

```yaml
- id: corr-powershell-then-egress
  type: correlation
  title: Encoded PowerShell followed by an outbound connection
  level: High
  group_by: host
  window_seconds: 120
  steps:
    - rule: win-suspicious-powershell-script-block
    - rule: sysmon-network-connection-to-remote-port
```

The engine groups stored alerts by host, user or address, looks for the ordered sequence inside the window, and writes a new alert that names the events it was built from. A rule can require fewer steps than it lists (`min_steps`), which is how "three failed logons and then a lockout" is expressed without listing every permutation. Re-running is safe: each correlation alert carries a deterministic external id, so the store's unique index absorbs the repeat.

## Importing a packet capture

```console
curl -F "file=@lab.pcap" http://127.0.0.1:5000/api/pcap
```

A capture is read into **one event per flow** plus one per DNS name, with the packet count and byte count on each flow, and written into the same store as the host events. That is what makes the two joinable: a Sysmon process event and a network flow can be correlated on host and time. Reading a capture needs Scapy; everything else runs without it.

## Threat intelligence

Point `--intel-db` at the SQLite store written by the [Threat Intelligence Aggregator](../threat-intelligence-aggregator) and every event is checked against it as it arrives. An address, domain, hash or URL that matches raises an alert that names the indicator and the feed it came from. An event that was already an alert keeps the rule that fired and records the indicator alongside it, rather than having its reason replaced.

## Retention, alerting and authentication

- **Retention.** `--retain-days` prunes events older than the window, on a timer, so the store does not grow without limit. The default is 30 days; `0` disables it. Correlation alerts expire with the events they were built from, because a sequence finding is only checkable while its events are still there.
- **Alerting.** `--alert-log` appends every alert as a JSON line; `--alert-webhook` POSTs it. `--alert-min-severity` sets the floor (default `Medium`). A webhook that fails is recorded and shown on the dashboard rather than stopping collection.
- **Authentication.** `--auth-token`, or the `SIEM_AUTH_TOKEN` environment variable, requires a bearer token on every route. Left unset, the console is open on `127.0.0.1`, which is the documented default for a lab. When a token is set, open the page as `/?token=...` and it will authenticate its own requests.

## Routes

| Route | Purpose |
| --- | --- |
| `GET /health` | Confirms the app is up, and reports the rule and indicator counts. |
| `GET /api/dashboard` | The whole dashboard snapshot, with every filter accepted as a query parameter. |
| `GET /api/rules` | Every loaded detection and correlation rule, its ATT&CK techniques and its documented false positives. |
| `POST /api/events` | Ingest one event object or a list of them. |
| `POST /api/import` | Upload a JSON, JSONL, NDJSON or CSV file (3 MB limit). |
| `POST /api/pcap` | Upload a `.pcap`, `.pcapng` or `.cap` capture. |
| `POST /api/correlate` | Run the correlation rules over stored alerts now. |
| `POST /api/events/clear` | Empty the live store. |

Bad input comes back as JSON with a 400 and a sentence explaining the problem, never as an HTML error page: a missing message field, a severity outside High/Medium/Low, a CSV whose rows do not match the header width, a deeply nested JSON document, a `since` value that is not a whole number of minutes, or a file that is not a capture. A batch is validated before insertion, so one bad record does not leave half an import behind.

## How the collector works

`windows_collector.py` reads records from the channels it can reach, converts each one into a payload, and hands it to the ingestion pipeline. Classification is not decided in the collector: the payload goes to the rule engine, so a detection changes by editing a rule file.

The channels are `Security`, `System`, `Application`, `Microsoft-Windows-Sysmon/Operational`, Windows Defender and PowerShell. **Sysmon is the one that matters most**, because it records the command line of a new process, the process that started it, and the connections it makes. The Security log tells you an account logged on; Sysmon tells you what ran and what it talked to.

Records are deduplicated on the way in, and the collector keeps retrying a channel that is temporarily unavailable instead of giving up. Reading the Security channel depends on the account and machine policy, so seeing fewer channels than your colleague is normal and does not mean the app is broken.

**The collector excludes its own output.** Reading a channel means running PowerShell, and a running PowerShell writes to the PowerShell channel — so without a filter the monitoring tool becomes the loudest thing in its own store. Measured on a quiet workstation before this was fixed: 717 of 819 stored events were PowerShell console lifecycle records produced by the collector's own child processes, about nine in ten. Every PowerShell process the collector starts has its process id recorded, and records from those processes are counted and skipped. The dashboard reports the count next to the collector activity line, so the exclusion is visible rather than silent. Process ids are remembered to a bounded depth, because Windows reuses them.

## Limits

Read this before treating a clean dashboard as a clean machine.

- **One host.** The collector reads the machine it runs on. Events from other machines have to be shipped in through `POST /api/events` or an import; there is no agent, no forwarding protocol and no multi-host enrolment. A real SIEM's defining feature is many sources correlated together, and this has one live source.
- **A local lab console, not a hardened service.** With no `--auth-token` there is no authentication, and the Flask development server is doing the serving. It is not designed to face a network you do not control.
- **Scale.** SQLite with `LIKE` queries and a 300-row page is fine for a workstation's event log and will not survive millions of events. There is no hot/warm/cold tiering, no index beyond the two on the table, and no sharding.
- **Rule coverage is a documented subset of Sigma.** Unsupported keys are refused rather than ignored, so a rule that loads is a rule that works, but a Sigma rule using an unsupported feature will not load as-is.
- **Correlation is sequence-only.** Ordered steps on a single grouping field inside a time window. There are no thresholds, no joins across fields, and no baselining of what is normal for a host.
- **Severity is not risk.** A severity on an alert is how much attention the rule thinks it deserves, not a measure of business impact. There is no asset criticality and no risk scoring.
- **The collector reads the log by running PowerShell.** Six channels are polled every two seconds, one process each. That works and it is what the platform gives without an extra dependency, but it is heavy, it produces the self-generated volume described above, and a machine with a slow PowerShell profile will poll slowly. A native API would be the right long-term answer.

## Tests

```console
python -m pytest -q tests
```

The suite covers empty startup, Windows and Sysmon event mapping, rule loading and matching, the condition operators, severity ordering, correlation sequencing and its window and grouping, capture parsing into flows, threat-intelligence matching, retention, schema migration from an older store, notification, authentication, the collector's exclusion of its own processes, the API surface, the `since` bounds, and the JavaScript controls exercised in Node against a temporary API. A separate test reads real System events on Windows and is skipped elsewhere.
