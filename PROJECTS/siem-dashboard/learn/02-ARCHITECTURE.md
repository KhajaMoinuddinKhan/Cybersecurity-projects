# Architecture

1. An agent on another machine collects events, reusing the Windows collector or tailing a JSONL/CSV file, and POSTs batches to `/api/ingest` authenticated by its host key. The console's own collector reads its local channels the same way.
2. Ingestion of an agent batch normalises each event through `schema.py`, which detects the source and maps it onto the canonical record, then hands the batch to classification.
3. Classification applies threat intelligence and the rule engine, records the rule id, name, ATT&CK techniques and which selections matched, and decides whether the match may alert.
4. Validation normalises the batch and inserts it, with SQLite enforcing source and external-id uniqueness so a repeated import or a re-read channel cannot duplicate.
5. Correlation reads stored rule hits, groups them by host, user or address, and looks for the ordered sequence each correlation rule describes inside its window.
6. Flask builds filtered snapshots and serves the dashboard, the rules and schema endpoints, the ingestion routes, the host registry, the triage queue, the suppression manager, the audit log, the first-run pair that claims an unclaimed console, and the wave-two surface: the query-language search and its index, the baseline build and deviation endpoints, the lockout and MFA endpoints, and the backup list, create and verify routes. Accounts, hosts, triage state, baselines and events all live in the same file.
7. The browser polls every 1.5 seconds and renders the counters, charts, rankings, the triage queue, the host inventory, the suppression list, the audit table and the wave-two panels alongside the event stream.

## The loops

Collection, correlation, retention and browser refresh all run separately, and that separation is deliberate. An agent adds a fifth loop of its own: collect, drain its spool, ship, and spool again if the server is unreachable.

The collector reads each channel in sequence and inserts what it finds. The correlation worker re-examines recent rule hits on a timer, so a sequence that completes after its first event was stored is still found. The retention worker prunes by age and by volume, because a store bounded only by time grows without limit on a busy machine. The browser asks for a snapshot every 1.5 seconds, and the page asks the identity and the wave-two endpoints on the same rhythm.

Two of the wave-two features are deliberately not on a timer. A baseline is built when an administrator asks for it, not on every poll, because it reads a week of history; a backup is taken when an operator asks for it, not automatically, because where snapshots go and how many to keep is an operational choice. Neither runs in the collection path, so pausing the browser or stopping the collector changes nothing about them.

Pausing the browser leaves collection, correlation and retention running. An unreachable server does not stop an agent collecting; it moves the events to the spool. Stopping the collector does not stop the rule engine from classifying anything that arrives through the API or an agent.

[Run instructions and troubleshooting](../README.md)

[Back to the project guide](../README.md)
