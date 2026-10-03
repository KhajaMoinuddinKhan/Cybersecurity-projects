# Implementation

- `sha256_file()` reads files in one-megabyte chunks.
- `file_metadata()` records the digest, size, modification time and mode in one place.
- `files_under()` sorts discovered paths and prunes excluded directories, so the saved data is stable and quiet.
- `build_baseline()` records each file; `save_baseline()` writes formatted JSON and `load_baseline()` checks the top-level structure.
- `diff()` compares hashes for existing files, reports a mode-only difference as `PERMISSIONS`, and separately finds new and missing paths.
- `scan()` and `compare_baseline()` expose the same comparison with and without the per-change detail.
- `watch_scans()` re-scans on an interval and `watch_command()` prints each scan and returns the exit status.

## Inputs and failure handling

Create a folder called `watched` and put a few files in it before running the commands. The first command records their current contents; the second compares them with that saved state. The baseline path is relative to your terminal directory unless you provide an absolute path.

Use `--create` only when you intend to accept the current files as the new baseline; it overwrites the chosen baseline file. Keep a trusted copy separate from the data being monitored. Fix file-access or invalid-baseline errors before treating a comparison as complete. `--report` is refused together with `--watch`, and `--interval` must be greater than zero, because neither combination has a clear meaning.

[Back to the project guide](../README.md)
