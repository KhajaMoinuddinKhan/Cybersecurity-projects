# Concepts

- SHA-256 produces a content digest that changes when file content changes.
- A baseline records the expected state of a directory at a known point in time.
- Relative paths let the baseline describe files without depending on an absolute folder location.
- Added, modified, removed and permission states separate the main kinds of integrity change.
- Exclude patterns keep noise out of a report, and a watch interval decides how often the folder is re-read.

## Interpreting the evidence

An unchanged folder prints `No integrity changes detected.` Editing a file produces `MODIFIED`; creating or deleting one produces `ADDED` or `REMOVED`; changing permissions without touching the bytes produces `PERMISSIONS`. File size and modification time are recorded and shown as the detail of a modification, but the content hash is what decides whether a file changed, so a file whose contents and permissions are the same is not reported just because its timestamp moved. The baseline file itself is excluded when it sits inside the watched folder, and cache directories and editor temporary files are excluded by built-in patterns.

Watch mode re-reads the folder on an interval and compares each scan with the previous one, so a change is printed once as it appears. It is polling, not a kernel event stream, so a change that comes and goes between two scans is invisible. The tool does not record ownership, and a scan is not an atomic filesystem snapshot.

[Back to the project guide](../README.md)
