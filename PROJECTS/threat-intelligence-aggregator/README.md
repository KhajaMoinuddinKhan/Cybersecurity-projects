# Threat Intelligence Aggregator

Indicator feeds arrive as CSV, JSON, or something a vendor invented last quarter. This tool takes one or several of them — files, a directory of files, or URLs fetched over HTTP — normalises every indicator by type, merges duplicates across sources, keeps the result in SQLite, and lets you search, summarise, export or expire it. The interesting parts are still the boring ones: deciding what counts as the same indicator, escaping a search term properly, and failing with a message that says what is actually wrong.

It aggregates the feeds you point it at. It is not a subscription to a commercial intelligence provider, and a stored indicator means only that the value appeared in a feed you imported.

## Running it

Standard library only, including SQLite and the HTTP client:

```console
python -m src.aggregator --feed sample_feed.csv --db threat_intel.db
python -m src.aggregator --search "198.51.100.23" --db threat_intel.db
```

The bundled `sample_feed.csv` holds three indicators, so a first run looks like this:

```
$ python -m src.aggregator --feed sample_feed.csv --db threat_intel.db
Imported 3 new indicators (0 updated).

$ python -m src.aggregator --search 198.51.100.23 --db threat_intel.db
type    value                                    sources                             age  confidence
ip      198.51.100.23                            lab-feed                             0d  0.60
```

Import the same file again and it reports `Imported 0 new indicators (3 updated).` The count is new records, not rows read, and the repeat is still recorded as a fresh observation.

### Several sources in one run

`--feed` takes a file and can be repeated, `--feed-url` fetches a URL over HTTP and can be repeated, and `--feed-dir` imports every `.csv` and `.json` file in a directory. They can be combined in one command. Importing both feeds into an empty database at once, given a second feed that repeats the IP from the bundled sample and adds a domain, a SHA-256 hash and one malformed row:

```
type,value,source
ip,198.51.100.23,vendor-b
domain,login.evil.example.,vendor-b
hash,275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,vendor-b
ip,999.1.1.1,vendor-b
```

```console
python -m src.aggregator --feed sample_feed.csv --feed vendor_b.csv --db threat_intel.db
```

```
Imported 5 new indicators (1 updated).
Skipped 1 malformed entry: 1 x not a valid IP address or CIDR range: '999.1.1.1'.
```

The repeated IP is merged, not stored twice, and the malformed row is skipped rather than failing the whole feed. Every indicator is tagged with the feed it came from: an explicit `source` column wins, and a row without one is tagged with the file name or the feed URL.

### Fetching feeds

`--feed-url` downloads a feed with `urllib`, waiting at most `--http-timeout` seconds (15 by default). A URL that cannot be retrieved stops the run with a message naming the URL:

```
Feed operation failed: could not retrieve http://127.0.0.1:1/nope.csv: <urlopen error timed out>
```

## Feed formats

CSV needs a `type` column and a `value` column; a `source` column is optional and is what makes a result traceable back to the feed it came from. JSON is a list of objects with the same field names. The format is chosen by file extension, or by the first non-space character for a URL without one. A byte order mark at the start of the file is accepted.

A structural problem — a missing required column, an invalid JSON document, an oversized CSV field, a deeply nested JSON file, a feed that is not valid UTF-8 — stops the run with an error naming the file or the column. A single malformed *row* does not: it is skipped, counted, and reported with the reason, and the rest of the feed is imported.

## Normalisation and validation

Every value is checked and rewritten to one canonical form before it is stored:

- **IP** — an IPv4 or IPv6 address is validated and compressed (`2001:0DB8::0001` becomes `2001:db8::1`); a CIDR range is kept, with a host address inside a network reduced to the network (`198.51.100.23/24` becomes `198.51.100.0/24`). Anything that is not a valid address or range is rejected.
- **Domain** — lowercased and stripped of a trailing dot (`EVIL.Example.COM.` becomes `evil.example.com`). The check is deliberately loose: whitespace, a slash, a colon, an at-sign or an empty label is rejected, but it does not attempt full RFC 1035 validation, so unusual-but-real feed entries survive.
- **Hash** — lowercased and accepted only if its hexadecimal length names an algorithm: 32 (MD5), 40 (SHA-1), 64 (SHA-256) or 128 (SHA-512). A hex string of any other length is rejected.
- **URL** — the scheme and host are lowercased and a trailing slash is dropped. A value without a scheme and host is rejected.

Rejected rows are never stored, and the run prints how many were skipped and why.

## De-duplication, merging and confidence

SQLite enforces uniqueness on `(type, value)` of the canonical form, so `EVIL.test` and `evil.test` are one indicator, not two. The same indicator seen in several feeds becomes one record that keeps the first `source` that reported it and, in a companion table, one row per reporting feed. Each record tracks a `first_seen` and `last_seen` timestamp and an observation count that rises every time the indicator is reported, including on a re-import.

Confidence is derived from breadth and freshness, not from any judgement about the indicator:

```
confidence = 0.6 * min(1, sources / 3) + 0.4 * max(0, 1 - age_days / 30)
```

rounded to two places. One fresh source scores 0.6, two score 0.8, three or more score 1.0; an indicator not seen for 30 days has lost all of its freshness weight. It is recomputed on every import and expiry.

## Expiry

`--expire-days` prunes indicators not seen within the window and reports what it removed:

```console
python -m src.aggregator --expire-days 90 --db threat_intel.db
```

```
Pruned 0 stale indicators (not seen in 90 days).
```

Nothing is pruned when the store is fresh. A row whose last-seen time is unknown is left alone, because there is no age to judge it by.

## Search, stats and export

`--search` matches a literal substring across every indicator type. `%`, `_` and `\` are escaped, so searching for `%` finds a percent sign rather than matching everything. Each hit names its type, value, every reporting source, its age and its confidence:

```
$ python -m src.aggregator --search example --db threat_intel.db
type    value                                    sources                             age  confidence
domain  bad-domain.example                       lab-feed                             0d  0.60
domain  login.evil.example                       vendor-b                             0d  0.60
```

`--stats` counts the store by type, by reporting source and by age band:

```
$ python -m src.aggregator --stats --db threat_intel.db
Total indicators: 5
By type:
  domain   2
  hash     2
  ip       1
By source:
  lab-feed                       3
  vendor-b                       3
By age:
  0-7d     5
  7-30d    0
  30-90d   0
  90d+     0
  unknown  0
```

`--export PATH` writes the whole store to CSV or JSON, chosen by the file extension or forced with `--export-format`:

```console
python -m src.aggregator --export intel.csv --db threat_intel.db
```

```
Exported 5 indicators to intel.csv.
```

The columns are `type, value, source, sources, first_seen, last_seen, observations, confidence, age_days, age_band`.

## Scope and limits

This aggregates the feeds you point it at. It does not subscribe to a commercial intelligence provider, verify feed authenticity, or decide whether an indicator is trustworthy: confidence measures how many independent feeds reported a value and how recently, and nothing more. A match tells you that an indicator appears in the data you imported, which is a much weaker statement than "this is malicious".

URL canonicalisation only lowercases the scheme and host and drops a trailing slash; it does not reorder query parameters or otherwise guess that two URL spellings are the same. Domain validation is intentionally loose. The store is a plain SQLite file, and an indicator is only as current as the last feed you imported.

The schema keeps its original `type`, `value` and `source` columns, so a store written by an earlier version of this tool is upgraded in place and the SIEM dashboard's `--intel-db` option keeps working.

## Tests

```console
python -m pytest -q tests
```

The suite covers type normalisation and validation, deduplication and merging across sources, the confidence formula, expiry, search and stats across every type, CSV and JSON export, HTTP fetching against a local server, and the command-line messages. No test touches the internet.
