# SIEM Dashboard

This is the largest project here, and the only one that watches a live system. It collects Windows Event Log records, classifies them into alerts with an explainable rule for each one, stores everything in SQLite, and serves a dashboard you can filter while the data is still arriving.

If you want to see how collection, validation, storage, detection and an analyst view fit together, start here. If you only want to read a capture file, the traffic tools are a much smaller commitment.

## Running it

```console
python -m pip install -r requirements.txt
python -m src.app
```

That starts the dashboard on `http://127.0.0.1:5000` with a fresh store at `siem_live.db` and begins collecting from the available Windows channels. Useful variations:

```console
python -m src.app --db lab.db --port 5001     # different store and port
python -m src.app --reset                     # clear the live store first
python -m src.app --no-windows-events         # run the API without the collector
```

`--no-windows-events` is what you want on macOS or Linux, or on a Windows account that cannot read the security channel: the dashboard, the import endpoints and the filters all work, they simply have no live source feeding them.

## What you get

The page updates from the current contents of the database, so nothing on it is decorative. Counts, severity breakdowns, events-per-minute, timelines, providers, Event IDs and the event table are all computed from stored records, and the search, time, channel, provider, Event ID, user, severity and alerts-only filters apply to everything on screen. The event table and CSV export show up to 300 matching rows.

Behind the page there are five routes:

| Route | Purpose |
| --- | --- |
| `GET /health` | Confirms the app is up and names the database in use. |
| `GET /api/dashboard` | The whole dashboard snapshot, with every filter accepted as a query parameter. |
| `POST /api/events` | Ingest one event object or a list of them. |
| `POST /api/import` | Upload a JSON, JSONL or CSV file (3 MB limit). |
| `POST /api/events/clear` | Empty the live store. |

Bad input comes back as JSON with a 400 and a sentence explaining the problem, never as an HTML error page: a missing message field, a severity outside High/Medium/Low, a CSV whose rows do not match the header width, a deeply nested JSON document, or a `since` value that is not a whole number of minutes. A batch is validated before insertion, so one bad record does not leave half an import behind.

## How the collector works

`windows_collector.py` reads records from the channels it can reach, maps the interesting event IDs to a severity, an alert flag and a rule name, and hands the result to the API for storage. Rules are event-based rather than text-based, so an audit log being cleared or a new service being installed is recognised from the event itself. Records are deduplicated on the way in, and the collector keeps retrying a channel that is temporarily unavailable instead of giving up.

The whole thing runs on `127.0.0.1` by default. It is a local lab console, not a hardened service: there is no authentication, and the Flask development server is doing the serving.

## Requirements and platform notes

Flask and psutil. The collector needs Windows; everything else runs anywhere. Reading the Security channel depends on the account and machine policy, so seeing fewer channels than your colleague is normal and does not mean the app is broken.

## Tests

```console
python -m pytest -q tests
```

Twenty-nine tests cover empty startup, Windows event mapping and classification, deduplication, filters, JSON/JSONL/CSV import and its edge cases, atomic validation, dashboard metrics, the `since` bounds, and the JavaScript controls exercised in Node against a temporary API. A separate test reads real System events on Windows and is skipped elsewhere.
