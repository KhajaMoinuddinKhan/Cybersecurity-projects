# Threat Intelligence Aggregator

Indicator feeds arrive as CSV, JSON, or something a vendor invented last quarter. This tool takes a small feed, normalises it into one shape, keeps it in SQLite, and lets you search it. The interesting parts are the boring ones: deciding what counts as a duplicate, escaping a search term properly, and failing with a message that says what is actually wrong with the file.

## Running it

Standard library only, including SQLite:

```console
python -m src.aggregator --feed sample_feed.csv --db threat_intel.db
python -m src.aggregator --search "198.51.100.23" --db threat_intel.db
```

The bundled `sample_feed.csv` holds three indicators, so a first run looks like this:

```
Imported 3 new IOCs.

ip      198.51.100.23                            lab-feed
```

Import the same file again and it reports `Imported 0 new IOCs.` The count is new records, not rows read.

## Feed formats

CSV needs a `type` column and a `value` column; a `source` column is optional and is what makes a result traceable back to the feed it came from. JSON is a list of objects with the same field names. Type names are trimmed and normalised on the way in, and unknown types are rejected rather than stored.

A missing required column, an invalid JSON document, an oversized CSV field, a deeply nested JSON file, a feed that is not valid UTF-8, and a byte order mark at the start of the file are all handled: the BOM is accepted, and the rest produce a clear error naming the file or the column. Nothing is inserted until the whole file has been parsed and validated.

## Deduplication, precisely

SQLite enforces uniqueness on `(type, value)`, so duplicates are dropped by the database rather than by a growing set in memory. The comparison is byte for byte, which means it is case-sensitive: `EVIL.test` and `evil.test` are stored as two indicators. That is a deliberate choice, not an oversight — the tool does not canonicalise URL forms or guess that two spellings mean the same thing, and it does not merge source histories, so the first source that reported an indicator stays attached to it.

Search is a literal `LIKE` match with `%`, `_` and `\` escaped, so searching for `%` finds records containing a percent sign instead of matching everything.

## Scope

This stores what you give it. It does not fetch feeds, score confidence, expire stale indicators, or decide whether an indicator is trustworthy. A match tells you that an indicator appears in the data you imported, which is a much weaker statement than "this is malicious".

## Tests

```console
python -m pytest -q tests
```

Tests cover normalisation and validation, deduplication counts, literal search including wildcard characters, byte-order-mark and undecodable feeds, oversized fields, deep JSON, missing columns, and the command-line messages for an empty search.
