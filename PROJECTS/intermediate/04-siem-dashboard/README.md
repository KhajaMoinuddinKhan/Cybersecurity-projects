# MKMK Live SIEM

## Overview

MKMK Live SIEM is a local Flask and SQLite security monitoring project for Windows. It does not load a fixed demo dataset. On startup it reads recent records from available Windows Event Log channels, stores them in a separate live database, then continues collecting new records while the dashboard is running.

The dashboard is driven by the current contents of `siem_live.db`. Event totals, security alerts, severity counts, events per minute, timelines, providers, Event IDs, filters, and event tables all change from collected data.

## Windows data sources

The collector attempts to read:

- Security
- System
- Application
- Microsoft-Windows-Windows Defender/Operational
- Microsoft-Windows-PowerShell/Operational

Channels that are unavailable are shown as unavailable in the dashboard. Reading the Security channel can require an elevated PowerShell session.

The collector imports a small number of the most recent real records on startup so the dashboard has context, then polls for new records every two seconds. Duplicate Windows records are ignored using the channel and Windows Record ID.

## Security rules

The project marks specific Windows events as security alerts, including failed logons, account lockouts, account creation/deletion, privileged-group membership changes, audit-log clearing, service installation, Windows Defender detections, and suspicious PowerShell script blocks. Other Windows records remain visible as telemetry and keep their severity based on the Windows event level.

## Run

From this project directory:

```powershell
python -m pip install -r requirements.txt
python -m src.app
```

Open `http://127.0.0.1:5000`.

The default database is `siem_live.db`, separate from the older `siem.db` used by earlier versions of this project. No sample records are inserted.

Use `python -m src.app --reset` to start with an empty live database. New Windows records will continue to arrive after the collector starts.

Use `python -m src.app --no-windows-events` only when you want to run the interface without the Windows collector.


## Dashboard controls

The compact sidebar links to overview, alerts, sources, measured server health, events and import. Search, time, channel, provider, Event ID, user, severity and alerts-only filters update the view. Reset clears filters. Live/Paused controls automatic refresh. Details opens the raw event. Export current view downloads the visible event rows as CSV. Import accepts JSON, JSONL, NDJSON and CSV. Clearing the store requires confirmation.

Charts use current filtered events; no random values or sample records are inserted. The trend and volume charts show up to 20 active minute buckets. The event table and export show up to 300 matching rows; the alert table shows up to 30. Counts cover the full matching dataset. Server health uses real psutil readings from the machine running the SIEM. Connection loss displays a stale-data notice.

Unavailable or inaccessible Windows channels remain visible and retry. No matching Windows events is a normal empty poll.

## Tests

```powershell
python -m pip install pytest
python -m pytest -q tests
```

The JavaScript control test runs with Node.js when installed and uses a temporary event store. These test fixtures never populate the normal live database. Native Windows Event Log collection must be checked on Windows with the necessary channel permissions.

## Output

### Dashboard overview

![Live SIEM dashboard overview](assets/siem-dashboard-overview.png)

### Event stream

![Live SIEM event stream](assets/siem-dashboard-event-stream.png)

These screenshots show the dashboard running on Windows with collected events, measured system health, provider activity, and event triage.
