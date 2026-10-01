# Challenges

- The baseline must come from a trusted state or the comparison has little value.
- Hashing a large directory can take time and disk I/O.
- The project tracks file content and presence, not ownership, permissions, or process activity.
- A changed file still needs human review to determine why it changed.

## Working within the scope

This is an on-demand comparison, not a background watcher. It does not record permissions, ownership, or the process responsible for a change. File symlinks can be followed, so choose a folder whose contents and links you understand. A scan is not an atomic filesystem snapshot; files changing while they are read can make a result inconsistent.

Create two files and save a baseline. Edit the first file, remove the second, and add a third. The next comparison should report all three change types. Run a second comparison without changing anything else: the same findings remain until you deliberately create a new baseline.

[Back to the project guide](../README.md)
