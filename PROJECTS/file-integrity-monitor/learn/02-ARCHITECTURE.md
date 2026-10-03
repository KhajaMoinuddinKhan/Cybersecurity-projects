# Architecture

1. Create mode walks the target folder and records each file's hash, size, modification time and mode.
2. The baseline is saved as JSON with each relative path and its metadata.
3. Compare mode loads the saved baseline and builds a fresh view of the folder.
4. `scan()` compares both views and returns sorted change records that carry a type, path and detail.
5. `compare_baseline()` keeps the older two-tuple view of the same records.
6. The command line prints the changes as text or JSON, optionally writes a report file, and sets the exit status.
7. Watch mode runs the same comparison on an interval and prints each scan's new changes.

## Follow one run

`sha256_file()` reads one-megabyte chunks so a large individual file does not have to fit in memory. `files_under()` skips an excluded directory before it is entered and keeps the walk finite across a Windows junction. `build_baseline()` records relative paths, hashes and metadata in a stable order, and `diff()` checks both directions so deleted files are not missed. Baseline loading validates each stored digest before comparison. In watch mode the first scan is compared with the saved baseline and every later scan with the one before it, so `watch_scans()` yields one list of changes per interval and the `--count` option bounds how many times it does so.

The split between scanning and comparing is what makes watch mode possible. `scan()` walks the tree once and returns a rich `Change` record for everything it finds, holding the content hash and the metadata together. `compare_baseline()` then reduces those records against a stored baseline to the `(kind, path)` pairs the original two-shot mode reported, which is why the older interface still works unchanged. Watch mode simply calls the same scan again and compares against the previous scan rather than the saved baseline, so a change is announced once, at the moment it appears, instead of being re-reported on every pass.

[Back to the project guide](../README.md)
