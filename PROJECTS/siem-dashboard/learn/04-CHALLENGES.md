# Challenges

- Windows channel access depends on OS permissions and enabled logging. Security usually requires an elevated session, and a channel that is not installed is not the same as one that is broken, so the collector separates the two.
- Channels retry after failures; empty polls are normal and do not disable collection.
- A host's liveness is self-reported. A machine switched off without telling anyone reads as `online` until the stale window passes, and there is no heartbeat beyond the agent invoking the server.
- An agent is a forwarder, not an endpoint agent. It has no installer, no service registration and no tamper protection, and it does not sign its payloads, so the key proves a key was presented rather than which machine sent a batch. The spool it writes when the server is unreachable is unencrypted text that may hold credentials from event messages.
- Accounts arrive with their own exposure. TLS is opt-in, so without `--tls-cert` and `--tls-key` a session is only as safe as the plain-HTTP transport; roles are enforced at the routes rather than by the database; and the console is open until the first account exists, which is the lab default and a poor one on a shared network.
- A lockout is also a denial of service. It is keyed on a username-and-address pair, so an attacker who knows a username can lock that user out from their own address, and one who has a pool of addresses still gets the threshold from each. It is a speed bump on guessing, not a wall.
- A second factor guards the password, not the file. The TOTP secret is stored in plaintext in the same SQLite file as the events, so anyone who can read the database can generate valid codes and anyone who can write it can turn the factor off.
- Search answers with two engines that do not agree. FTS5 matches whole tokens and the fallback scan matches substrings, so `dmin` finds `admin` on one and not the other; the response names the engine that ran so the difference is visible, but it is a difference to expect rather than a bug.
- The unclaimed console is the weakest state it has. Before the first account exists there is no access control at all on loopback and every action is recorded against an implicit local operator, so the audit log cannot say who did anything. That is a reasonable default for a laptop and a poor one the moment the port is reachable from anywhere else. The related trap is a page that asks for a sign-in the server cannot accept: a form is only useful when there is an account behind it, and the first-run card exists because a prompt nobody can satisfy is worse than no prompt.
- Suppression is easy to misuse. It hides a detection from the queue without stopping the rule firing or the event being stored, so suppressing a true positive hides it exactly as well as a false one.

## Coverage is part of the result

A connected dashboard is not evidence of complete log coverage. Channel permissions, disabled logs, bounded startup backfill, sequential polling, downtime and log resets all affect what is available, and the collector state belongs in the notes of any investigation alongside the findings.

Two limits are worth stating plainly because they are easy to forget while looking at a busy page. A baseline now exists, but it is a volume statistic: it cannot see an attack that stays inside normal volume, it knows nothing about correlation between keys, and it does not change how a rule alerts, which is why the noisiest ones still record themselves as context. And search is backed by an FTS5 index only when the build has one and the index is in step; the fallback is a column scan, not a full-text index, and the two do not match the same rows. Both live in a single SQLite file served by a single process.

[Run instructions and troubleshooting](../README.md)

[Back to the project guide](../README.md)
