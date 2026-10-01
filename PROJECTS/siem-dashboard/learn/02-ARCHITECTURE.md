# Architecture

1. The Windows collector polls configured channels through PowerShell and retries errors.
2. Validation normalizes events and prevents duplicate collector records.
3. SQLite persists events in siem_live.db.
4. Flask builds filtered snapshots and serves API and file ingestion routes.
5. The browser polls every 1.5 seconds, renders charts and tables, and supports pause, details and CSV export.
6. psutil measures CPU, memory and disk usage for the server-health panel.

## Two independent loops

Collection and browser refresh are separate loops. PowerShell reads each channel in sequence and the collector inserts normalized records into SQLite. The browser asks Flask for a new snapshot every 1.5 seconds. Pausing the browser leaves collection active; losing access to one channel does not imply that the page or the other channels are unavailable.

[Run instructions and troubleshooting](../README.md)
