# Overview

Threat Intelligence Aggregator imports simple CSV or JSON indicator feeds into SQLite. It accepts IP, domain, hash, and URL records, removes duplicates by type and value, and supports local substring searches.

The source code in `src/` contains the implementation.
