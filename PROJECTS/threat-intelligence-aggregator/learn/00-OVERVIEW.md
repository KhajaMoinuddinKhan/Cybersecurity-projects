# Overview

Threat Intelligence Aggregator turns a set of indicator feeds into one searchable SQLite store. A feed is a CSV or JSON document with `type` and `value` fields. In a single run you can pass several files, several URLs, and a directory; each indicator is normalised and validated by type, merged with any duplicate from another feed, and tagged with the source it came from.

## A useful first exercise

Import `sample_feed.csv`, then import it again and compare the counts. The first run reports three new indicators; the second reports zero new but three updated, because the repeat is recorded as a fresh observation rather than a second record. Then run `--stats` and `--search` to see the age and the confidence the store now carries.

The tool validates the shape and type of each indicator — that an IP parses, that a hash's length names an algorithm, that a domain is lowercased — but it does not judge whether the indicator is malicious. Confidence is a count of independent sources combined with a measure of freshness, not a reputation score. Expiry is driven by the `--expire-days` option when you run it, not by a schedule.

[Back to the project guide](../README.md)
