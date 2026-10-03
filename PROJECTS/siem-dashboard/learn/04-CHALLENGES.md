# Challenges

- Windows channel access depends on OS permissions and enabled logging. Security usually requires an elevated session, and a channel that is not installed is not the same as one that is broken, so the collector separates the two.
- Channels retry after failures; empty polls are normal and do not disable collection.
- The timeline shows the latest active minute buckets, not a continuous zero-filled window. Event tables show a bounded number of matching events and CSV export exports that visible view.
- Native PowerShell execution requires testing on Windows. Elsewhere the tests validate conversion, rule evaluation, query construction and retry behaviour with controlled inputs.
- This is a local single-machine pipeline with no concept of a user. Authentication is optional and off by default, one shared token is the only access control, and nothing records who queried what. The development server binds to localhost.

## Coverage is part of the result

A connected dashboard is not evidence of complete log coverage. Channel permissions, disabled logs, bounded startup backfill, sequential polling, downtime and log resets all affect what is available, and the collector state belongs in the notes of any investigation alongside the findings.

Two limits are worth stating plainly because they are easy to forget while looking at a busy page. There is one live host: events from other machines have to be shipped in through the API or an import, and there is no agent or forwarding protocol. And there is no baselining, so the rules cannot say whether an event is unusual *for this host* — which is why the noisiest ones record themselves as context rather than raising alerts.

[Run instructions and troubleshooting](../README.md)

[Back to the project guide](../README.md)
