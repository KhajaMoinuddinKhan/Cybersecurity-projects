# Architecture

1. The command line accepts a feed path, a search term, or both.
2. `read_feed()` parses CSV or JSON and normalizes each row.
3. `import_iocs()` writes unique indicators to SQLite with `INSERT OR IGNORE`.
4. `search_iocs()` performs a parameterized substring lookup.
5. The command line prints import totals and matching indicators.
