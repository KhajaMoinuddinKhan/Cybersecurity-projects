# Implementation

- `VALID_TYPES` limits stored indicator categories to a small known set.
- `normalise_row()` trims values, supplies a default source, and rejects invalid rows.
- The database schema applies `UNIQUE(type, value)` to support deduplication.
- CSV parsing uses `DictReader`, while JSON input expects a list of records.
- Search results return the indicator type, value, and source.

## Inputs and failure handling

CSV needs `type` and `value` columns and can include `source`. JSON uses a list of objects with the same fields. Supported types are `ip`, `domain`, `hash`, and `url`. Fields must be text; an omitted or blank source becomes `local`. The bundled feed is a small training fixture, not a current threat feed.

Use the same `--db` path for import and search. Different terminal directories can otherwise create different databases with the same filename. Invalid JSON, missing feed files, and non-text fields produce a clear command-line error; fix the feed before retrying.

[Back to the project guide](../README.md)
