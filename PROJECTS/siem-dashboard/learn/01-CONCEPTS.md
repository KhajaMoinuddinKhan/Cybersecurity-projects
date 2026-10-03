# Concepts

- A host is a machine in the registry, not just a name on an event. It is enrolled once, receives a key, and reports through an agent; its status is computed when it is read, so `online`, `stale` and `never-reported` describe a reporting relationship rather than a stored flag.
- An enrolment key is shown once. The server stores only a salted PBKDF2 hash, so the plaintext exists only in the enrolment response and in the agent that received it. Losing it means rotating, not recovering.
- A session and a bearer key are different kinds of proof. A session identifies a person who signed in with a password; a host key identifies a machine that was enrolled. The console keeps them apart, which is why `/api/ingest` stays reachable while every analyst route needs a login.
- An unclaimed console is not a locked one. With no accounts the console is open on loopback and identity reads as an implicit local administrator, so the page offers to create the first account rather than showing a sign-in form nobody could satisfy. The first-run door refuses a second attempt, which is what stops it being a way to mint extra accounts.
- A role is a set of actions, and the matrix is one dict. A viewer watches, an analyst works the queue, an admin manages the console. The server enforces the matrix at each route; the database only stores the role name.
- A detection is an event that matched a rule and was allowed to alert. Its triage status is separate from its severity: severity is how much attention the rule thinks the event deserves, status is where the investigation has got to.
- Suppression is a tuning decision, not a detection decision. It hides a rule's detections from the queue; it does not stop the rule firing or the event being stored.
- The canonical record is one shape every source is mapped onto, so a Windows event, a Sysmon event, a packet flow and a JSON line all reach storage with the same fields. Unknown fields survive in `raw`.
- A baseline describes a host's own behaviour, not a rule's. For each host and key it stores the mean and standard deviation of that key's hourly counts, and a deviation is a recent count far above that mean. A key with too few samples is reported as insufficient rather than judged, and hours with no events are excluded so a host that is off overnight does not lower its own baseline.
- A lockout is keyed on a username-and-address pair, not a username. Five failures from one address lock that pair for fifteen minutes and the lockout expires on its own; a locked pair is refused before the password is checked.
- A second factor is one more proof at the login step, not a property of the session. TOTP proves the person holds the enrolled secret; once a session is issued it is still a bearer token. The secret lives in the same database as the data, so it guards against a stolen password, not against someone who already has the file.
- A search engine is a fact to report, not to hide. The same query can be answered by an FTS5 index, which matches tokens, or by a column scan, which matches substrings, so the response names which one ran rather than letting the two be confused.
- A backup is a snapshot of a file, not a second server. It is taken with SQLite's own backup API so committed data in the write-ahead log is included, and it is verified by reading it back, because an unverified copy is a guess.
- An unavailable metric is not a zero. CPU, memory and disk are measured on the machine running the application, and a panel that cannot reach its endpoint says so rather than drawing a bar at zero.
- A failed login is worth recording. The audit log keeps successes and failures, because an authentication system that records only what worked cannot show an attack.

## Severity, alerts and time

Severity is the level used to organise events, while the alert flag is a separate decision. An operational error can be High without matching a security rule, and a rule can match without raising an alert at all. Timestamps are normalised to UTC, and the events-per-minute value counts records whose event timestamp falls in the last minute, so a historical import raises the totals without raising that rate.

[Run instructions and troubleshooting](../README.md)

[Back to the project guide](../README.md)
