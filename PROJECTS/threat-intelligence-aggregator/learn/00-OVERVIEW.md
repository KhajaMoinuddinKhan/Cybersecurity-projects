# Overview

Threat Intelligence Aggregator imports simple CSV or JSON indicator feeds into SQLite. It accepts IP, domain, hash, and URL records, removes duplicates by type and value, and supports local substring searches.

## A useful first exercise

Import `sample_feed.csv` twice and compare the counts. Then search for just part of an indicator and inspect the returned source. This separates two concerns: deduplication keeps storage tidy, while the source helps you decide how much weight to give a match.

Deduplication is exact for indicator values. It does not canonicalize URL forms or merge source histories: the first stored source remains attached to a duplicate. The tool validates structure, not whether an IP, domain, hash, or URL is a trustworthy indicator. It has no automatic feed updates, confidence scoring, or expiry mechanism.

[Back to the project guide](../README.md)
