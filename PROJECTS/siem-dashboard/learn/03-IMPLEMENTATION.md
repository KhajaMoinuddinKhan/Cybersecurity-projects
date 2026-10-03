# Implementation

- `agent.py` runs on a reporting machine. It collects through `windows_collector` or by tailing a file, ships batches to `/api/ingest` with the host key, and spools unsent events as JSONL when the server cannot be reached.
- `schema.py` defines the canonical event record and the four per-source mappers, auto-detected from each record.
- `auth.py` owns accounts, the role and permission matrix, scrypt password hashing, hashed session tokens and the audit log. It answers permission questions but enforces nothing itself.
- `hosts.py` is the registry: enrolment, key hashing and verification, the last-seen clock and the computed online, stale and never-reported status.
- `triage.py` adds status, assignee, append-only notes, transitions and suppressions on top of stored detections, in its own tables.
- `search.py` owns the query grammar, the FTS5 index and its triggers, the scan fallback and the engine report. `baseline.py` owns the hourly bucketing, the per-key mean and standard deviation, the minimum-sample guard and the deviation test. `security.py` owns the login-attempt record, the lockout and the TOTP and recovery-code machinery. `backup.py` owns the snapshot, verify, restore and prune operations.
- `rules.py`, `correlation.py`, `pcap_ingest.py`, `enrichment.py`, `notify.py` and `windows_collector.py` are unchanged in role: rules, sequences, captures, indicators, alerting and the native log reader.
- `app.py` owns storage, the HTTP surface, retention, the shared token, the workers, the route-level enforcement of the permission matrix, and the TLS context.
- `ingest_payloads` validates and classifies a complete batch before inserting any of it. The production application inserts no generated sample records.

## Decisions worth explaining

**An enrolment key is shown once.** `POST /api/hosts` returns the plaintext key and stores only a salted PBKDF2-HMAC-SHA256 hash, the same shape as real agent enrolment. The key cannot be read back, so a lost key is rotated rather than looked up, and a stolen database does not yield a usable key.

**Notes are append-only.** The triage module deliberately provides no update or delete for a detection note. An investigation record that could be silently rewritten would destroy the evidence the workflow exists to keep, so the only way to change the record is to append to it.

**Suppression expiry is read-time.** A suppression stores an expiry and is tested when it is read, so an expired one stops applying with no cleanup job. A malformed expiry compares as expired, which fails closed.

**Normalisation happens at ingest.** The agent forwards events in the payload shape the collector already produces; the server is what maps them onto the canonical record, so one schema governs every source.

**A baseline does not judge thin history.** A key with fewer than the minimum samples is not stored and is not tested, and empty hours are left out of the sample rather than counted as zero. Both choices trade recall for honesty: the module would rather report a key as insufficient than invent an alert from three hours of data.

**A lockout is checked before the password.** The login route asks whether the pair is locked before it verifies anything, so a locked account cannot be used to tell a right password from a wrong one. The lockout carries its own expiry and a read never deletes it, so the audit trail survives.

**The first-run door closes behind you.** `POST /api/setup` creates the first administrator and is refused the moment any account exists, so it is a way to claim an unclaimed console and not a way to mint an extra account; later accounts come from an administrator. The reply carries the session it just issued, so claiming the console lands the operator signed in rather than at a form. While no account exists the console reports identity as an implicit local administrator, because answering 401 there made the page ask for credentials that could not exist yet.

**A backup is taken with SQLite, not copied.** The store is in WAL mode, so a byte copy of the file can miss committed transactions still in the log; the online backup API reads a consistent snapshot while the server keeps writing, and the result is one self-contained file with no sidecars.

[Run instructions and troubleshooting](../README.md)

[Back to the project guide](../README.md)
