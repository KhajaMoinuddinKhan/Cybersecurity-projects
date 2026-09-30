# Implementation

- `VALID_TYPES` limits stored indicator categories to a small known set.
- `normalise_row()` trims values, supplies a default source, and rejects invalid rows.
- The database schema applies `UNIQUE(type, value)` to support deduplication.
- CSV parsing uses `DictReader`, while JSON input expects a list of records.
- Search results return the indicator type, value, and source.
