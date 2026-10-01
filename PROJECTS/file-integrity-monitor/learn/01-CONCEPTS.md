# Concepts

- SHA-256 produces a content digest that changes when file content changes.
- A baseline records the expected state of a directory at a known point in time.
- Relative paths let the baseline describe files without depending on an absolute folder location.
- Added, modified, and removed states separate the main kinds of integrity change.

## Interpreting the evidence

An unchanged folder prints `No integrity changes detected.` Editing a file produces `MODIFIED`; creating or deleting one produces `ADDED` or `REMOVED`. File size is recorded for context, but the content hash determines whether a file changed. The baseline file itself is excluded when it sits inside the watched folder.

This is an on-demand comparison, not a background watcher. It does not record permissions, ownership, or the process responsible for a change. File symlinks can be followed, so choose a folder whose contents and links you understand. A scan is not an atomic filesystem snapshot; files changing while they are read can make a result inconsistent.

[Back to the project guide](../README.md)
