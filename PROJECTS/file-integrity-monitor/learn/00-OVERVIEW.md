# Overview

File Integrity Monitor creates a SHA-256 baseline for files in a folder and compares later scans with that baseline. It records each file's size, modification time and mode alongside the hash, reports files as added, modified, removed, or as a permission change, and stores the baseline as readable JSON.

## A useful first exercise

Create two files and save a baseline. Edit the first file, remove the second, add a third, and change the permissions on one of them. The next comparison should report all four change types, and a clean second comparison should print `No integrity changes detected.` The findings remain until you deliberately create a new baseline.

Run the same comparison with `--watch --count 3 --interval 2` and the tool re-scans three times, printing any new change on the scan where it appears. A change is reported once, not on every interval, because each scan is compared with the one before it. `--json` prints the report as JSON, `--report` writes it to a file, and the command exits non-zero whenever changes were found so a scheduler can tell.

Watch mode polls; it does not use kernel file-system events, so a file created and deleted between two scans is missed. The tool does not record ownership, and a scan is not an atomic snapshot. File symlinks can be followed, so choose a folder whose contents and links you understand.

[Back to the project guide](../README.md)
