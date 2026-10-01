# Architecture

1. The command line accepts a feed path, a search term, or both.
2. `read_feed()` parses CSV or JSON and normalizes each row.
3. `import_iocs()` writes unique indicators to SQLite with `INSERT OR IGNORE`.
4. `search_iocs()` performs a parameterized substring lookup.
5. The command line prints import totals and matching indicators.

## Follow one run

`read_feed()` parses the entire file and validates its rows before import. `normalise_row()` trims text and normalizes the type name. SQLite enforces uniqueness on `(type, value)`, and parameterized queries perform substring searches. Connections are closed after each operation, and a failed transaction is rolled back.

CSV needs `type` and `value` columns and can include `source`. JSON uses a list of objects with the same fields. Supported types are `ip`, `domain`, `hash`, and `url`. Fields must be text; an omitted or blank source becomes `local`. The bundled feed is a small training fixture, not a current threat feed.

[Back to the project guide](../README.md)
