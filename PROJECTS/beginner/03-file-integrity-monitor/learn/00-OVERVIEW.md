# Overview

File Integrity Monitor creates a SHA-256 baseline for files in a folder and compares later scans with that baseline. It reports files as added, modified, or removed and stores the baseline as readable JSON.

## A useful first exercise

Create two files and save a baseline. Edit the first file, remove the second, and add a third. The next comparison should report all three change types. Run a second comparison without changing anything else: the same findings remain until you deliberately create a new baseline.

This is an on-demand comparison, not a background watcher. It does not record permissions, ownership, or the process responsible for a change. File symlinks can be followed, so choose a folder whose contents and links you understand. A scan is not an atomic filesystem snapshot; files changing while they are read can make a result inconsistent.

[Back to the project guide](../README.md)
