# Implementation

- windows_collector.py converts native records, extracts EventData, and applies security rules.
- ingest_payloads validates a complete batch before inserting it.
- dashboard_snapshot queries live counts, provider rankings and minute buckets.
- system_metrics reads psutil measurements and reports unavailable data.
- dashboard.html implements filters, charts, event details, export, import and pause/resume.
- The production application inserts no generated sample records. Tests use isolated temporary databases.

## Validation before persistence

Each ingestion batch is normalized before the database write begins. CSV is checked for consistent columns, JSON alert flags must be booleans, and invalid severities are rejected. SQLite enforces source/external-ID uniqueness for collector records. Database connections are explicitly closed after transactions, which matters when repeated polling would otherwise leave connections waiting for garbage collection.

[Run instructions and troubleshooting](../README.md)
