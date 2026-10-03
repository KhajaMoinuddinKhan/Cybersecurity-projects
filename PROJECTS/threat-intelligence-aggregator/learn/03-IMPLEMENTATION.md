# Implementation

- `VALID_TYPES` limits stored indicator categories to a small known set.
- `canonicalise_value()` validates and rewrites a value for its type: IP addresses and CIDR ranges through `ipaddress`, domains lowercased and stripped, hashes checked against their algorithm length, URLs with a lowercased scheme and host.
- `normalise_row()` trims fields, supplies a default source, and rejects non-text fields, an unknown type or an unparseable value.
- `import_indicators()` merges duplicates, tracks every source in `ioc_sources`, and refreshes the confidence of each touched indicator.
- `compute_confidence()` is the only place confidence is calculated, so the stored value and the displayed value agree.

## Inputs and failure handling

CSV needs `type` and `value` columns and can include `source`; JSON is a list of objects with the same fields. Fields must be text; an omitted or blank source becomes the feed's own label — the file name or the URL. A structural problem raises a clear command-line error, while a malformed row is skipped and the run prints how many were skipped and why.

Use the same `--db` path for every operation. Different terminal directories can otherwise create different databases with the same filename. The store is upgraded in place, so an older database is safe to point the tool at.

[Back to the project guide](../README.md)
