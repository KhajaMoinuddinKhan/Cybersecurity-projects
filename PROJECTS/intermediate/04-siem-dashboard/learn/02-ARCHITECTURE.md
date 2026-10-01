# Architecture

1. The Windows collector polls configured channels through PowerShell and retries errors.
2. Validation normalizes events and prevents duplicate collector records.
3. SQLite persists events in siem_live.db.
4. Flask builds filtered snapshots and serves API and file ingestion routes.
5. The browser polls every 1.5 seconds, renders charts and tables, and supports pause, details and CSV export.
6. psutil measures CPU, memory and disk usage for the server-health panel.
