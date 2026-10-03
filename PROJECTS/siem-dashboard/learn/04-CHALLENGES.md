# Challenges

- Windows channel access depends on OS permissions and enabled logging. Security usually requires an elevated session, and a channel that is not installed is not the same as one that is broken, so the collector separates the two.
- Channels retry after failures; empty polls are normal and do not disable collection.
- A host's liveness is self-reported. A machine switched off without telling anyone reads as `online` until the stale window passes, and there is no heartbeat beyond the agent invoking the server.
- An agent is a forwarder, not an endpoint agent. It has no installer, no service registration and no tamper protection, and it does not sign its payloads, so the key proves a key was presented rather than which machine sent a batch. The spool it writes when the server is unreachable is unencrypted text that may hold credentials from event messages.
- Accounts arrive with their own exposure. There is no TLS, so a session is only as safe as the transport; roles are enforced at the routes rather than by the database; and the console is open until the first account exists, which is the lab default and a poor one on a shared network.
- Suppression is easy to misuse. It hides a detection from the queue without stopping the rule firing or the event being stored, so suppressing a true positive hides it exactly as well as a false one.

## Coverage is part of the result

A connected dashboard is not evidence of complete log coverage. Channel permissions, disabled logs, bounded startup backfill, sequential polling, downtime and log resets all affect what is available, and the collector state belongs in the notes of any investigation alongside the findings.

Two limits are worth stating plainly because they are easy to forget while looking at a busy page. There is still no baselining, so the rules cannot say whether an event is unusual *for this host*, which is why the noisiest ones record themselves as context rather than raising alerts. And search is still a SQL `LIKE` scan with paging rather than an indexed query language, over a single SQLite file served by a single process with no replication and no backup.

[Run instructions and troubleshooting](../README.md)

[Back to the project guide](../README.md)
