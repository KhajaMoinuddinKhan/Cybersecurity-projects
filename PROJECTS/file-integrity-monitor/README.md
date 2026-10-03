# File Integrity Monitor

Sometimes the question is not "is this file dangerous" but "has this file changed since I last looked". This tool answers that one: it records the SHA-256 hash, size, modification time and permissions of every file in a folder, and later tells you exactly which files were added, modified, removed, or had their permissions changed.

It is a baseline tool. The first run creates a trusted snapshot; every later run compares the folder against it. A watch mode can also re-scan on an interval and report each change as it appears.

## Running it

Standard library only. Create the baseline, then verify against it:

```console
python -m src.fim ./watched --baseline baseline.json --create
python -m src.fim ./watched --baseline baseline.json
```

`--baseline` defaults to `baseline.json` in the current directory. The tool excludes its own baseline file from the comparison, so you can keep the baseline inside the folder you are watching without it appearing as a change.

### Watching for changes

`--watch` re-scans on an interval instead of running once:

```console
python -m src.fim ./watched --baseline baseline.json --watch --interval 2
```

Each scan compares the folder with the previous scan, so a change is printed once when it appears rather than on every interval. `--interval` is in seconds and defaults to 5. Add `--count` to stop after a fixed number of scans, which is what makes the loop scriptable and easy to test:

```console
python -m src.fim ./watched --baseline baseline.json --watch --interval 2 --count 10
```

Without `--count` it runs until you stop it with Ctrl+C. Watch mode polls the filesystem; it does not subscribe to kernel file-system events, so a file that is created and deleted between two scans is never seen.

### Excluding files

Cache directories and editor leftovers would otherwise fill the report, so a set of built-in patterns is always applied: `__pycache__`, `*.py[cod]`, `.git`, `.hg`, `.svn`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.tox`, `.DS_Store`, `Thumbs.db`, `*.swp`, `*.swo`, `*.tmp`, `*~`, `.#*` and `#*#`. `--exclude` adds your own glob, and you can repeat it:

```console
python -m src.fim ./watched --baseline baseline.json --exclude '*.log' --exclude 'build'
```

A pattern is matched against the whole path relative to the folder and against every single path component, so `*.log` skips a log file anywhere in the tree and `build` skips that directory and everything under it. The built-in patterns always apply; `--exclude` adds to them rather than replacing them.

### Reports

`--json` prints the report as JSON instead of text, with the type, path and detail of every change:

```console
python -m src.fim ./watched --baseline baseline.json --json
```

`--report FILE` writes the same report to a file as well as printing it, and works with either format:

```console
python -m src.fim ./watched --baseline baseline.json --report findings.txt
python -m src.fim ./watched --baseline baseline.json --json --report findings.json
```

`--report` is not accepted in watch mode, where a report would be ambiguous.

## What the output looks like

A clean folder reports one line:

```
No integrity changes detected.
```

After adding a file, editing another, changing the permissions on a third and deleting a fourth:

```
Integrity changes detected:
  ADDED       three.txt
  MODIFIED    one.txt (size, mtime)
  PERMISSIONS config.txt (0o100666 -> 0o100444)
  REMOVED     two.txt
Summary: 1 added, 1 modified, 1 removed, 1 permissions
```

Each result is one of `ADDED`, `MODIFIED`, `REMOVED` or `PERMISSIONS`, and the path is relative to the folder you passed in. The text after the path is the detail: which recorded metadata moved for a content change, or the old and new mode for a permission change. The last line counts the changes of each type.

Watch mode prints one line per scan and the changes it found:

```
Watching watched every 0.2s, stopping after 1 scan.
Scan 1: 2 changes
  ADDED       four.txt
  MODIFIED    one.txt (size, mtime)
```

The command exits with a non-zero status when changes were found and zero when the folder matched, so it can be used directly as a check:

```console
python -m src.fim ./watched --baseline baseline.json || echo "changed"
```

In watch mode the exit status is non-zero if any change was seen across all the scans.

## How it works

`build_baseline()` walks the folder, hashes each file in one-megabyte chunks so a large file does not need to fit in memory, and records the digest with the file size, modification time and mode. `compare_baseline()` rebuilds that picture and diffs it against the stored one.

The content digest decides whether a file was modified. `size` and `mtime` are recorded and shown as the detail of a modification, but a file whose contents and permissions are unchanged is not reported just because its timestamp moved, so touching a file is not a change. A permission change on a file whose bytes are identical is reported as its own `PERMISSIONS` change, separate from a content change.

`load_baseline()` validates the file before anything is compared: it must be a JSON object, and every entry must carry a 64-character hexadecimal SHA-256 digest. A baseline saved by an editor that writes a UTF-8 byte order mark still loads, and a digest written in upper case is normalised rather than rejected, because hex is case-insensitive. A baseline written before metadata was tracked still loads too; the fields it does not carry are simply not compared.

## Where it is useful, and where it is not

This is the right tool for a small folder you care about: configuration directories, a lab web root, a set of scripts you have audited. It is not a replacement for a real endpoint agent. It has no alerting, no signature database, and no protection against someone who edits the baseline as well as the files.

Watch mode is polling. It re-walks the folder on each interval rather than subscribing to kernel file-system events, so a file created and deleted between two scans is never seen, and a short interval trades CPU and disk I/O for the chance of catching a brief change. There is still no scheduler and no daemon: run it under a task scheduler, a cron job, or your own loop if you want it to run on a schedule.

Ownership (the user and group that own a file) is not tracked, because the standard library does not expose it usefully on Windows, where a permission change is only the read-only flag. A scan is also not an atomic filesystem snapshot; files changing while they are read can make a result inconsistent.

## Tests

```console
python -m pytest -q tests
```

The tests cover added, modified and removed files, a baseline stored inside the watched folder, invalid baseline metadata, a byte-order-mark baseline, upper-case digests, the metadata and permission comparison, the exclude patterns, the text and JSON reports, the report file, the exit codes, and a single watch iteration against a real temporary folder.
