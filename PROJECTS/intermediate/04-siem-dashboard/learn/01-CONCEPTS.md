# Concepts

- Events are telemetry; security alerts are events that match an explainable detection rule.
- Filters apply to totals, charts, source rankings and event triage.
- Parameterized SQL and literal search escaping keep searches predictable.
- Collector health and dashboard connectivity are separate: an accessible dashboard can have unavailable Windows channels.
- CPU, memory and disk values are measured on the machine running Flask. Unavailable metrics are shown explicitly.

## Severity, alerts, and time

Severity is the level used to organize events, while is_alert is a separate detection flag. An operational error can be High without matching a security rule. Timestamps are normalized to UTC, and the events-per-minute value counts records whose event timestamp falls in the last minute. Historical imports can raise total counts without raising that rate.

[Run instructions and troubleshooting](../README.md)
