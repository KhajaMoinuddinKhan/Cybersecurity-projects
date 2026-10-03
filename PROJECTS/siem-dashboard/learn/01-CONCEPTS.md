# Concepts

- Events are telemetry. Alerts are events that matched a rule. Context is an event that matched a rule which is not allowed to raise an alert on its own. Keeping those three apart is what stops a dashboard from being either silent or unreadable.
- Detection rules are data. They live in files, they carry a stable id, and editing a detection means editing a file rather than the application.
- A rule that matches normal background traffic records itself and stays out of the queue. Without a notion of what is normal for a host, treating that traffic as context is more honest than pretending a browser is an incident.
- Filters apply to totals, charts, source rankings and the event table together, so what the numbers describe and what the table shows are always the same set.
- Correlation matches on rule hits rather than on alerts, which is what lets a context rule be a step in a sequence.
- Enrichment answers a different question from detection. A rule says an event looks wrong; threat intelligence says whether the address, domain or hash involved is already known to be bad.
- Collector health and dashboard connectivity are separate. An accessible dashboard can have unavailable channels, and the page says which.
- CPU, memory and disk values are measured on the machine running the application. Unavailable metrics are shown as unavailable rather than as zero.

## Severity, alerts and time

Severity is the level used to organise events, while the alert flag is a separate decision. An operational error can be High without matching a security rule, and a rule can match without raising an alert at all. Timestamps are normalised to UTC, and the events-per-minute value counts records whose event timestamp falls in the last minute, so a historical import raises the totals without raising that rate.

[Run instructions and troubleshooting](../README.md)

[Back to the project guide](../README.md)
