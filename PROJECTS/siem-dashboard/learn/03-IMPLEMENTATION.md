# Implementation

- `agent.py` runs on a reporting machine. It collects through `windows_collector` or by tailing a file, ships batches to `/api/ingest` with the host key, and spools unsent events as JSONL when the server cannot be reached.
- `schema.py` defines the canonical event record and the four per-source mappers, auto-detected from each record.
- `auth.py` owns accounts, the role and permission matrix, scrypt password hashing, hashed session tokens and the audit log. It answers permission questions but enforces nothing itself.
- `hosts.py` is the registry: enrolment, key hashing and verification, the last-seen clock and the computed online, stale and never-reported status.
- `triage.py` adds status, assignee, append-only notes, transitions and suppressions on top of stored detections, in its own tables.
- `rules.py`, `correlation.py`, `pcap_ingest.py`, `enrichment.py`, `notify.py` and `windows_collector.py` are unchanged in role: rules, sequences, captures, indicators, alerting and the native log reader.
- `app.py` owns storage, the HTTP surface, retention, the shared token, the workers, and the route-level enforcement of the permission matrix.
- `ingest_payloads` validates and classifies a complete batch before inserting any of it. The production application inserts no generated sample records.

## Decisions worth explaining

**An enrolment key is shown once.** `POST /api/hosts` returns the plaintext key and stores only a salted PBKDF2-HMAC-SHA256 hash, the same shape as real agent enrolment. The key cannot be read back, so a lost key is rotated rather than looked up, and a stolen database does not yield a usable key.

**Notes are append-only.** The triage module deliberately provides no update or delete for a detection note. An investigation record that could be silently rewritten would destroy the evidence the workflow exists to keep, so the only way to change the record is to append to it.

**Suppression expiry is read-time.** A suppression stores an expiry and is tested when it is read, so an expired one stops applying with no cleanup job. A malformed expiry compares as expired, which fails closed.

**Normalisation happens at ingest.** The agent forwards events in the payload shape the collector already produces; the server is what maps them onto the canonical record, so one schema governs every source.

[Run instructions and troubleshooting](../README.md)

[Back to the project guide](../README.md)
