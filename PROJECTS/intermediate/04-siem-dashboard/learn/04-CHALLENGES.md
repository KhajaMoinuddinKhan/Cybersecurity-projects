# Challenges

- Windows channel access depends on OS permissions and enabled logging. Security usually requires an elevated session.
- Channels retry after failures; empty polls are normal and do not disable collection.
- The timeline shows the latest 20 active minute buckets, not a continuous zero-filled window. Event tables show the latest 300 matching events; CSV export exports that visible view.
- Native PowerShell execution requires testing on Windows; Linux tests validate conversion, query construction and retry behavior with controlled inputs.
- This local single-machine SIEM has no authentication and binds to localhost by default. Detection rules flag selected events; analysts still need to investigate.

## Coverage is part of the result

A connected dashboard is not evidence of complete log coverage. Channel permissions, disabled logs, bounded startup backfill, sequential polling, downtime, and log resets all affect what is available. Record the collection state alongside an investigation. The collector can also appear in PowerShell telemetry, so review the underlying messages before interpreting a busy provider as suspicious.

[Run instructions and troubleshooting](../README.md)
