# MKMK Live SIEM

## Overview

MKMK Live SIEM is a local Flask and SQLite security monitoring project for Windows. It does not load a fixed demo dataset. On startup it reads recent records from available Windows Event Log channels, stores them in a separate live database, then continues collecting new records while the dashboard is running.

The dashboard is driven by the current contents of \`siem_live.db\`. Event totals, security alerts, severity counts, events per minute, timelines, providers, Event IDs, filters, and event tables all change from collected data.

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

\`\`\`powershell
python -m pip install -r requirements.txt
python -m src.app
\`\`\`

Open \`http://127.0.0.1:5000\`.

The default database is \`siem_live.db\`, separate from the older \`siem.db\` used by earlier versions of this project. No sample records are inserted.

Use \`python -m src.app --reset\` to start with an empty live database. New Windows records will continue to arrive after the collector starts.

Use \`python -m src.app --no-windows-events\` only when you want to run the interface without the Windows collector.
