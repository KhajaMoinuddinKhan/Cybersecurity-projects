# Challenges

- The baseline must come from a trusted state or the comparison has little value.
- Hashing a large directory can take time and disk I/O, and watch mode repeats that work on every interval.
- The project tracks content, size, modification time and mode, not ownership or process activity.
- Polling can miss a file that is created and deleted between two scans.
- A changed file still needs human review to determine why it changed.

## Working within the scope

Watch mode is polling, not a kernel file-system event stream. A short interval catches changes sooner but costs more CPU and disk I/O, and a file that comes and goes between two scans is never seen. The tool does not record ownership, and a scan is not an atomic filesystem snapshot, so files changing while they are read can make a result inconsistent.

Create two files and save a baseline. Edit the first file, remove the second, add a third, and change the permissions on one of them. The next comparison should report all four change types, and a second comparison without further edits should stay clean. Use `--count` when you want watch mode to stop on its own, and rely on the non-zero exit status to let a scheduler act on the findings.

[Back to the project guide](../README.md)
