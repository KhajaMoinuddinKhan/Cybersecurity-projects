# Overview

MKMK Live SIEM collects real Windows Event Logs, stores normalized records in SQLite, and updates a black-and-red analyst dashboard. It starts empty unless real records are available. API and file ingestion support additional actual log sources.

## From counts to evidence

A useful session starts with collector health, then moves from a time window or channel to individual events. Open the raw record before deciding what an alert means. A service installation, for example, can be expected maintenance or an unexpected persistence mechanism; this dashboard provides the event context, not the final judgment.

[Run instructions and troubleshooting](../README.md)
