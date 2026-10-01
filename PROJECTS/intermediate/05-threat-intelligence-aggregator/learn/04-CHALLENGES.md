# Challenges

- The project does not verify feed authenticity or indicator reputation.
- It stores no confidence score, expiry time, or relationship data.
- Substring search is simple and can return broad matches.
- Badly formed feed rows are rejected instead of being repaired automatically.

## Working within the scope

Deduplication is exact for indicator values. It does not canonicalize URL forms or merge source histories: the first stored source remains attached to a duplicate. The tool validates structure, not whether an IP, domain, hash, or URL is a trustworthy indicator. It has no automatic feed updates, confidence scoring, or expiry mechanism.

Import `sample_feed.csv` twice and compare the counts. Then search for just part of an indicator and inspect the returned source. This separates two concerns: deduplication keeps storage tidy, while the source helps you decide how much weight to give a match.

[Back to the project guide](../README.md)
