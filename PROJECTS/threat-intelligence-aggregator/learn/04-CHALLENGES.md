# Challenges

- The project does not verify feed authenticity or indicator reputation.
- Confidence is a heuristic over source count and age, not a judgement of trust.
- Domain validation is loose by design, so unusual feed entries survive.
- URL canonicalisation is shallow: it does not treat two query-string orderings as the same URL.
- Substring search is simple and can return broad matches.

## Working within the scope

Deduplication now happens on the canonical form of a value, and merging keeps every source that reported an indicator. But the tool still validates shape, not truth: it cannot tell you whether an IP, domain, hash or URL is genuinely malicious, only that it appeared in a feed you imported and how many feeds said so. Expiry removes indicators that have gone quiet, which is housekeeping, not a claim that the ones that remain are still active.

Import `sample_feed.csv` twice and compare the counts, then run `--stats`. The repeat shows up as an increased observation count and a moved last-seen time rather than a new record, which is the difference between storing an indicator and storing its history.

[Back to the project guide](../README.md)
