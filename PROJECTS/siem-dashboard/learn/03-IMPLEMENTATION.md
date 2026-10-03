# Implementation

- `rules.py` loads the rule files, evaluates conditions against event fields, and splits detection rules from correlation rules. A rule that cannot be parsed stops the process rather than being skipped.
- `windows_collector.py` converts native records, extracts structured EventData, and excludes records the collector itself caused.
- `correlation.py` finds ordered sequences across stored rule hits and writes an alert that names the events it was built from.
- `pcap_ingest.py` turns a capture into one event per flow and one per DNS name, in the same store as the host events.
- `enrichment.py` matches events against the indicator store written by the threat-intelligence project.
- `notify.py` delivers alerts to a log file or a webhook, and reports a failure instead of stopping collection.
- `app.py` owns storage, the HTTP surface, retention, authentication and the workers.
- `ingest_payloads` validates and classifies a complete batch before inserting any of it.
- The production application inserts no generated sample records. Tests use isolated temporary databases.

## Two decisions worth explaining

**Excluding the collector's own output.** Reading a channel means running PowerShell, and a running PowerShell writes to the PowerShell channel, so without a filter the monitoring tool becomes the loudest source in its own store. The process ids of the PowerShell children the collector starts are recorded, and records that name one of them are counted and skipped. Two places have to be checked: a Windows channel record carries the process that raised it in the record header, while a Sysmon record carries Sysmon's own process id there and names the process the event is about in the event body. The skipped count is shown on the dashboard rather than hidden.

**Validation before persistence.** Each batch is normalised before the write begins. CSV is checked for consistent columns, alert flags must be booleans, invalid severities are rejected, and an unknown modifier in a rule is refused at load time. Database connections are explicitly closed after transactions, which matters when repeated polling would otherwise leave connections waiting for garbage collection.

[Run instructions and troubleshooting](../README.md)

[Back to the project guide](../README.md)
