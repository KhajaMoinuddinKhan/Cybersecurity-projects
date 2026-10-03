# Architecture

1. The Windows collector polls the configured channels through PowerShell, converts each record, and hands it to the pipeline. It never decides whether an event is an alert.
2. Classification applies threat intelligence and the rule engine to each payload, records the rule id, the rule name, the ATT&CK techniques and which selections matched, and decides whether the match is allowed to alert.
3. Validation normalises the batch and inserts it, with SQLite enforcing source and external-id uniqueness so a repeated import or a re-read channel cannot duplicate.
4. Correlation reads stored rule hits, groups them by host, user or address, and looks for the ordered sequence each correlation rule describes inside its time window.
5. Flask builds filtered snapshots and serves the dashboard, the rules endpoint, the ingestion routes and the capture import.
6. The browser polls every 1.5 seconds and renders the counters, charts, rankings, detection queue, correlation panel and event table.

## Four independent loops

Collection, correlation, retention and browser refresh all run separately, and that separation is deliberate.

The collector reads each channel in sequence and inserts what it finds. The correlation worker re-examines recent rule hits on a timer, so a sequence that completes after its first event was stored is still found. The retention worker prunes by age and by volume, because a store bounded only by time grows without limit on a busy machine. The browser asks for a snapshot every 1.5 seconds.

Pausing the browser leaves collection, correlation and retention running. Losing one channel does not imply the page or the other channels are unavailable. Stopping the collector does not stop the rule engine from classifying anything that arrives through the API.

[Run instructions and troubleshooting](../README.md)

[Back to the project guide](../README.md)
