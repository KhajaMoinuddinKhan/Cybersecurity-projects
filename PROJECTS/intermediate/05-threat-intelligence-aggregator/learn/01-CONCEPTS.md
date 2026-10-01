# Concepts

- Indicators of compromise can be stored as IP addresses, domains, hashes, or URLs.
- Normalization keeps feed records consistent before they enter storage.
- A uniqueness rule on type and value prevents duplicate indicator rows.
- Source metadata records where each imported indicator came from.
- Parameterized queries keep search values separate from SQL syntax.

## Interpreting the evidence

The import count reports newly inserted indicators, not every row read. Importing the bundled feed into an empty database adds three records; importing it again adds zero. A search prints the type, value, and original source for each matching record. `%` and `_` are treated literally rather than as search wildcards.

Deduplication is exact for indicator values. It does not canonicalize URL forms or merge source histories: the first stored source remains attached to a duplicate. The tool validates structure, not whether an IP, domain, hash, or URL is a trustworthy indicator. It has no automatic feed updates, confidence scoring, or expiry mechanism.

[Back to the project guide](../README.md)
