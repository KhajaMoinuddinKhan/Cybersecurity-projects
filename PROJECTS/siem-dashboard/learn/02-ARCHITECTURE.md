# Architecture

1. An agent on another machine collects events, reusing the Windows collector or tailing a JSONL/CSV file, and POSTs batches to `/api/ingest` authenticated by its host key. The console's own collector reads its local channels the same way.
2. Ingestion of an agent batch normalises each event through `schema.py`, which detects the source and maps it onto the canonical record, then hands the batch to classification.
3. Classification applies threat intelligence and the rule engine, records the rule id, name, ATT&CK techniques and which selections matched, and decides whether the match may alert.
4. Validation normalises the batch and inserts it, with SQLite enforcing source and external-id uniqueness so a repeated import or a re-read channel cannot duplicate.
5. Correlation reads stored rule hits, groups them by host, user or address, and looks for the ordered sequence each correlation rule describes inside its window.
6. Flask builds filtered snapshots and serves the dashboard, the rules and schema endpoints, the ingestion routes, the host registry, the triage queue, the suppression manager and the audit log. Accounts, hosts, triage state and events all live in the same file.
7. The browser polls every 1.5 seconds and renders the counters, charts, rankings, the triage queue, the host inventory, the suppression list and the audit table alongside the event stream.

## The loops

Collection, correlation, retention and browser refresh all run separately, and that separation is deliberate. An agent adds a fifth loop of its own: collect, drain its spool, ship, and spool again if the server is unreachable.

The collector reads each channel in sequence and inserts what it finds. The correlation worker re-examines recent rule hits on a timer, so a sequence that completes after its first event was stored is still found. The retention worker prunes by age and by volume, because a store bounded only by time grows without limit on a busy machine. The browser asks for a snapshot every 1.5 seconds, and the page asks the identity and triage endpoints on the same rhythm.

Pausing the browser leaves collection, correlation and retention running. An unreachable server does not stop an agent collecting; it moves the events to the spool. Stopping the collector does not stop the rule engine from classifying anything that arrives through the API or an agent.

[Run instructions and troubleshooting](../README.md)

[Back to the project guide](../README.md)
