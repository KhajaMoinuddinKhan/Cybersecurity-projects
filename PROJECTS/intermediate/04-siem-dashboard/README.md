# MKMK SIEM Dashboard

## Overview

MKMK SIEM Dashboard is a local Flask and SQLite SIEM lab. It accepts security events through a live JSON API, manual dashboard entry, or JSON/JSONL/CSV import, then updates event counts, severity filters, timelines, source activity, event types, and the event stream in real time.


## Live Windows collection

On Windows, `python -m src.app` starts a background collector for new System, Application, and Security Event Log records. The collector starts at the current end of each log, so it does not flood the dashboard with old history. New Windows records are normalized, stored in SQLite, and reflected in the dashboard on the next live refresh. If the Security log is not readable with the current permissions, System and Application continue collecting.

Use `python -m src.app --no-windows-events` to run the dashboard without the Windows collector.
