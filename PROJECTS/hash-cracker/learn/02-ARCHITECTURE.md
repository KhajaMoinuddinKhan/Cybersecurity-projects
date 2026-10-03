# Architecture

The CLI validates its arguments, then hands each target to a detection and parsing layer before any hashing happens. `detect_algorithms()` maps a digest's length and hexadecimal form to the algorithms that could have produced it, and `parse_target()` separates a digest from an embedded salt and records whether that salt is a suffix or a prefix. `resolve_algorithms()` turns that detection, an explicit `--algorithm`, and the `--all` flag into the algorithms actually tried.

The candidate source is a factory rather than a list: each algorithm gets a fresh iterator, so a wordlist is streamed and never held in memory even when several digests are tested in one run. `crack_target()` cracks one target and `crack_targets()` keeps per-target results and errors apart, so one ambiguous digest does not stop the others. A `CrackResult` makes success, failure, algorithm, salt, attempt count, duration and rate explicit, and `report_dict()` assembles the JSON work report from those results.

There is no network client in this architecture. This prevents the project from turning an educational hash comparison into a remote authentication attack.

[Back to the project guide](../README.md)
