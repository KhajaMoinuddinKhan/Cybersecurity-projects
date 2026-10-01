# File Integrity Monitor

When a file changes unexpectedly, it helps to know exactly what changed since the last trusted state. This tool saves a SHA-256 inventory of a folder and compares later scans against it, reporting added, modified, and removed files.

## Run it

Open a terminal in this project directory. Use Python 3.12 or 3.13; the repository's [setup guide](../../../README.md#get-started-in-vs-code) explains virtual environments and dependency installation.

```console
python -m src.fim ./watched --baseline baseline.json --create
python -m src.fim ./watched --baseline baseline.json
```

Create a folder called `watched` and put a few files in it before running the commands. The first command records their current contents; the second compares them with that saved state. The baseline path is relative to your terminal directory unless you provide an absolute path.

## Read the result

An unchanged folder prints `No integrity changes detected.` Editing a file produces `MODIFIED`; creating or deleting one produces `ADDED` or `REMOVED`. File size is recorded for context, but the content hash determines whether a file changed. The baseline file itself is excluded when it sits inside the watched folder.

## How the code works

`sha256_file()` reads one-megabyte chunks so a large individual file does not have to fit in memory. `build_baseline()` records relative paths, hashes, and sizes in a stable order. The comparison builds a fresh inventory and checks both directions so deleted files are not missed. Baseline loading validates each stored digest before comparison.

The [learning notes](learn/00-OVERVIEW.md) explain the concepts, implementation decisions, and tradeoffs in more detail.

## Try a small investigation

Create two files and save a baseline. Edit the first file, remove the second, and add a third. The next comparison should report all three change types. Run a second comparison without changing anything else: the same findings remain until you deliberately create a new baseline.

## Troubleshooting and scope

Use `--create` only when you intend to accept the current files as the new baseline; it overwrites the chosen baseline file. Keep a trusted copy separate from the data being monitored. Fix file-access or invalid-baseline errors before treating a comparison as complete.

This is an on-demand comparison, not a background watcher. It does not record permissions, ownership, or the process responsible for a change. File symlinks can be followed, so choose a folder whose contents and links you understand. A scan is not an atomic filesystem snapshot; files changing while they are read can make a result inconsistent.

## Tests

From this project directory, install pytest and run the tests:

```console
python -m pip install pytest
python -m pytest -q tests
```

Tests use controlled inputs and temporary files where needed. They verify the behavior of the configured checks; they do not establish that every real-world threat or configuration is covered.

## Output reference

![File Integrity Monitor](assets/file-integrity-monitor-demo.jpg)

The command output depends on your input. Use the run instructions above to reproduce a report with your own data.
