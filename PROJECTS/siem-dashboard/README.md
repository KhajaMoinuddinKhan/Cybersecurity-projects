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

## What it looks like

The page updates from the current contents of the database, so nothing on it is decorative. Counts, severity breakdowns, events-per-minute, timelines, providers, Event IDs, rule hits, ATT&CK techniques, the correlation panel and the event table are all computed from stored records, and the search, time, channel, provider, Event ID, user, rule, severity and alerts-only filters apply to everything on screen.

The three views below are from a live run on one machine, which is why the numbers are odd and specific rather than round. Yours will differ; the panels will not.

### The overview

![The overview, with the collector state, filters, counters, volume charts and channel health](docs/screenshots/01-overview.png)

The top strip answers the first question an analyst asks: **is this thing actually collecting anything?** It reports how many channels are live, when the page last refreshed, and — in the collector panel further down — the state of each channel individually. A channel that is not installed on the machine reads as `not installed` rather than as a failure, and one this account cannot read reads as `access denied`, because neither is a fault in the console.

The filter row is the workspace. Search covers the message, provider, event ID, user, host, address, rule name, rule id and ATT&CK technique in one box, and the dropdowns narrow by time window, channel, provider, event ID, user or rule. The severity buttons carry live counts of what each would show, so you can see the shape of the data before you filter it.

The counters along the top are the summary: total events in the current filter, how many of them matched a rule, how many are High, the rate per minute, and how many correlations have fired. Note that **alerts and High-severity events are different numbers** — an event can be High because Windows called it an error without matching any rule, and a rule can match without raising an alert at all.

Underneath, the volume timeline and the per-minute bars show *when* rather than *what*, the provider ranking shows where the data is coming from, and the severity donut shows the mix. The server-health panel measures the machine running the application, not the machine being monitored, and says so.

### The detection queue

![The detection queue, with rule ids and ATT&CK techniques, alongside technique and rule rankings](docs/screenshots/02-detection-queue.png)

This is the part that makes it a detection pipeline rather than a log viewer. Every row names the **rule that fired**, the **stable rule id** behind it, and the **ATT&CK technique** that rule is tagged with. A reader can disagree with a specific rule instead of arguing with a verdict, and because the id is stable, a rule can be renamed without losing the history of what it fired on.

The Event ID column is the raw Windows or Sysmon event that triggered it. In the screenshot the queue is showing LSASS memory reads, remote thread creation, and a signed system binary used to fetch a remote file — the techniques behind credential dumping, process injection and living-off-the-land downloads respectively. All three are real detections of real events, and all three are also the documented false positives for those rules, which is exactly why the rule files carry a `falsepositives` list: on a normal laptop, that is what these look like.

Below the queue, two rankings answer different questions. **Techniques seen in alerts** shows which ATT&CK techniques your environment is actually producing, which is a coverage view — techniques that never appear are either not happening or not being detected, and the rule files tell you which of those it is. **Rules that fired** shows which of your detections are earning their place, and which are noise you should tune or mark as context.

The correlation panel sits between them. It is empty in this screenshot, and an empty correlation panel is a real result rather than a broken one: no sequence of events matched a rule describing one. When it does fire, the row names the sequence and the host or user it happened on, and the events it was built from are recorded on the alert.

At the bottom of the panel, the runtime line states the current configuration — how many detection and correlation rules are loaded, the retention settings, and whether authentication is on. That line exists so a screenshot of a dashboard can be read without guessing what produced it.

### The live event stream

![The live event stream, with per-event detail, alongside the technique and rule rankings and the ingestion panel](docs/screenshots/03-event-stream.png)

Everything the rules did not flag is still here. The event table is the raw stream underneath the detections, filterable by the same controls, with the channel, provider, message, user and source address for each record. It is deliberately the largest panel on the page: an alert without the surrounding events is a claim, and the surrounding events are how you check it.

Selecting **Details** on any row opens the record in full: the normalised fields, the rule id and ATT&CK techniques if one matched, **which selections in the rule matched**, any threat-intelligence hit, and the raw event as it arrived. That last part matters. The stored record keeps the original, so a detection can be re-examined later against the data that produced it rather than against a summary someone wrote at the time.

**Export current view** writes exactly the rows on screen to CSV, which is the handover format: what you were looking at, when you were looking at it.

At the bottom, the ingestion panel is where additional sources arrive — a JSON, JSONL or CSV file, a packet capture, or another local collector posting to the API. Those land in the same store as the collected events, which is what makes a network flow and a process event on the same host joinable at all.

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
| `alert: false` | Match and record the rule, but do not raise an alert. For rules that describe normal background traffic |
| Anything else | Refused at load time with the file and the reason |

**A rule can match without raising an alert.** `alert: false` is for the rules that describe normal background traffic — a rule that matches every outbound connection would otherwise put hundreds of Medium alerts on the dashboard and bury the queue. The match is still recorded on the event with its rule id, so the rule can be a step in a correlation; it just does not appear in the detection queue on its own. The `/api/rules` response reports which rules alert and which do not.

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

The engine groups stored **rule hits** — not only alerts, so a rule marked `alert: false` can still be a step — by host, user or address, looks for the ordered sequence inside the window, and writes a new alert that names the events it was built from. A rule can require fewer steps than it lists (`min_steps`), which is how "three failed logons and then a lockout" is expressed without listing every permutation. Re-running is safe: each correlation alert carries a deterministic external id, so the store's unique index absorbs the repeat.

## Importing a packet capture

```console
curl -F "file=@lab.pcap" http://127.0.0.1:5000/api/pcap
```

A capture is read into **one event per flow** plus one per DNS name, with the packet count and byte count on each flow, and written into the same store as the host events. That is what makes the two joinable: a Sysmon process event and a network flow can be correlated on host and time. Reading a capture needs Scapy; everything else runs without it.

## Installing Sysmon

Sysmon is not part of Windows. The channel does not exist until you install it, and until then the collector reports that channel as `missing` rather than as an error.

A configuration for this project's rules is at [`sysmon-config.xml`](sysmon-config.xml). It enables exactly the event types the Sysmon rules can match on and nothing else, and it narrows two of them after measuring what they produce on a real laptop:

```console
sysmon64.exe -accepteula -i sysmon-config.xml
```

| Enabled | Why |
| --- | --- |
| `ProcessCreate` | Command line and parent image, which is what the execution rules match on |
| `NetworkConnect` | The second half of the correlation rule. External destinations only |
| `DnsQuery` | The long-name exfiltration rule |
| `ProcessAccess` | LSASS reads, filtered to that one target |
| `CreateRemoteThread` | The injection rule |
| `DriverLoad` | The driver rule |
| `ProcessTerminate` | **Off.** On by default, read by no rule, and the second-largest source of events |
| `FileCreate`, `RegistryEvent`, `PipeEvent`, `WmiEvent` | **Off.** No rule reads them and they are the noisiest things Sysmon produces |

Loopback, private and link-local destinations are excluded from `NetworkConnect`. A connection to `127.0.0.1` is not command and control, and on the measured machine those were most of the volume.

Re-apply a changed configuration without reinstalling:

```console
sysmon64.exe -c sysmon-config.xml
```

## Threat intelligence

Point `--intel-db` at the SQLite store written by the [Threat Intelligence Aggregator](../threat-intelligence-aggregator) and every event is checked against it as it arrives. An address, domain, hash or URL that matches raises an alert that names the indicator and the feed it came from. An event that was already an alert keeps the rule that fired and records the indicator alongside it, rather than having its reason replaced.

## Retention, alerting and authentication

- **Retention, by age and by volume.** `--retain-days` prunes events older than the window; `--max-db-mb` deletes the oldest events once the store passes a size. Whichever limit is reached first wins, and both are off at `0`. The age default is 30 days and the size default is 500 MB. Both are needed: Sysmon on a working laptop produced about 63 events a minute after tuning, which is 91,000 a day and roughly 6.8 GB over a 30-day window — a problem the age limit alone never sees. The current size and the cap are reported on the dashboard. Correlation alerts expire with the events they were built from, because a sequence finding is only checkable while its events are still there.
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

Records are deduplicated on the way in, and the collector keeps retrying a channel that is temporarily unavailable instead of giving up.

Each channel reports one of five states, and only the last of them is a problem with this application:

| State | Meaning |
| --- | --- |
| `connected` | Records are being read. |
| `waiting` | Not polled yet. |
| `missing` | The log does not exist on this machine. Sysmon shows this until Sysmon is installed. |
| `denied` | The log exists but this account cannot read it, which is common for `Security` on a managed machine. |
| `error` | A genuine failure. Only this state raises the summary line. |

Seeing fewer live channels than a colleague is normal and does not mean the app is broken.

**The collector excludes its own output.** Reading a channel means running PowerShell, and a running PowerShell writes to the PowerShell channel — so without a filter the monitoring tool becomes the loudest thing in its own store. Measured on a quiet workstation before this was fixed: 717 of 819 stored events were PowerShell console lifecycle records produced by the collector's own child processes, about nine in ten.

Every PowerShell process the collector starts has its process id recorded, and records from those processes are counted and skipped. The dashboard reports the count next to the collector activity line, so the exclusion is visible rather than silent. Process ids are remembered to a bounded depth, because Windows reuses them.

Two places have to be checked, and installing Sysmon is what made the second one obvious. A Windows channel record carries the process that raised it in the record header. A **Sysmon** record carries Sysmon's own process id there, and names the process the event is *about* in the event body — so a naive header check misses every Sysmon event about the collector's own children, and 87 of the first 107 process-creation events were the collector's PowerShell. The structured fields `ProcessId`, `SourceProcessId` and `ParentProcessId` are checked as well.

## Limits

Read this before treating a clean dashboard as a clean machine.

- **One host.** The collector reads the machine it runs on. Events from other machines have to be shipped in through `POST /api/events` or an import; there is no agent, no forwarding protocol and no multi-host enrolment. A real SIEM's defining feature is many sources correlated together, and this has one live source.
- **A local lab console, not a hardened service.** With no `--auth-token` there is no authentication, and the Flask development server is doing the serving. It is not designed to face a network you do not control.
- **Scale.** SQLite with `LIKE` queries and a 300-row page is fine for a workstation's event log and will not survive millions of events. There is no hot/warm/cold tiering, no index beyond the two on the table, and no sharding.
- **Rule coverage is a documented subset of Sigma.** Unsupported keys are refused rather than ignored, so a rule that loads is a rule that works, but a Sigma rule using an unsupported feature will not load as-is.
- **Correlation is sequence-only.** Ordered steps on a single grouping field inside a time window. There are no thresholds, no joins across fields, and no baselining of what is normal for a host.
- **Several rules are noisy by design and marked as context.** The outbound-connection rule matches normal traffic, so it records rather than alerts. That is a workaround for having no baselining: without a notion of what is normal for a host, the honest option is to treat the behaviour as context instead of pretending a browser is an incident.
- **Severity is not risk.** A severity on an alert is how much attention the rule thinks it deserves, not a measure of business impact. There is no asset criticality and no risk scoring.
- **Sysmon is a large source.** Even tuned, it is the bulk of the store — 1,031 of 1,157 events in one measured run. That is the nature of endpoint telemetry, and it is why the store is bounded by size as well as age.
- **The collector reads the log by running PowerShell.** Six channels are polled every two seconds, one process each. That works and it is what the platform gives without an extra dependency, but it is heavy, it produces the self-generated volume described above, and a machine with a slow PowerShell profile will poll slowly. A native API would be the right long-term answer.

## Tests

```console
python -m pytest -q tests
```

The suite covers empty startup, Windows and Sysmon event mapping, rule loading and matching, the condition operators, severity ordering, context rules that record without alerting, correlation sequencing and its window, grouping and step count, capture parsing into flows, threat-intelligence matching, retention by age and by volume, schema migration from an older store, notification, authentication, the collector's exclusion of its own processes, the channel-state classification, the API surface, the `since` bounds, and the JavaScript controls exercised in Node against a temporary API. A separate test reads real System events on Windows and is skipped elsewhere.
