# Architecture

1. The command line accepts feed files, feed URLs, a feed directory, and/or a search term, a stats flag, an export path or an expiry window.
2. `parse_feed_text()` parses CSV or JSON and normalises each row, recording a malformed row instead of failing the whole feed.
3. `fetch_feed()` downloads a URL with `urllib` and a timeout; a failure names the URL.
4. `import_indicators()` merges each indicator into SQLite, adding a source row and updating the timestamps, observation count and confidence.
5. `expire_iocs()`, `search_indicators()`, `collect_stats()` and `export_iocs()` prune or read the store.

## Follow one run

A file or URL is read into text, the format is chosen by extension or by the first character, and every row is normalised and validated by type. A structural error aborts the feed; a single bad row is skipped and counted. `import_indicators()` upserts the indicator into `iocs` and a per-source row into `ioc_sources`, then recomputes confidence from the source count and the last-seen time. SQLite enforces uniqueness on `(type, value)`.

The `iocs` table keeps its original `type`, `value` and `source` columns and adds `first_seen`, `last_seen`, `observations` and `confidence`; `ioc_sources` holds one row per indicator and feed. A store written by an earlier version is upgraded in place the first time it is opened, so the SIEM dashboard's `--intel-db` reader still finds the columns it expects. The bundled feed is a small training fixture, not a current threat feed.

[Back to the project guide](../README.md)
