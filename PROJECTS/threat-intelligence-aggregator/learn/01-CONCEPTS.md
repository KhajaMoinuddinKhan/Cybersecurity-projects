# Concepts

- Indicators of compromise are stored as IP addresses, domains, hashes, or URLs.
- Normalisation rewrites each value into one canonical form for its type.
- A uniqueness rule on type and canonical value collapses duplicates.
- Merging records every source that reported an indicator, alongside a first-seen and last-seen time and an observation count.
- Confidence combines source breadth with freshness.
- Expiry removes indicators that no feed has reported recently.

## Interpreting the evidence

The import count reports newly inserted indicators, not every row read. Importing the bundled feed into an empty database adds three records; importing it again adds zero, but updates their last-seen time and observation count. A search prints the type, value, every reporting source, the age and the confidence for each match. `%` and `_` are treated literally rather than as search wildcards.

Confidence is `0.6 * min(1, sources / 3) + 0.4 * max(0, 1 - age_days / 30)`: three independent fresh sources reach 1.0, one fresh source scores 0.6, and freshness fades to nothing after thirty days. It measures corroboration and recency, not whether an indicator is trustworthy.

[Back to the project guide](../README.md)
