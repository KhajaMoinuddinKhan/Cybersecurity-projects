# File Integrity Monitor

Sometimes the question is not "is this file dangerous" but "has this file changed since I last looked". This tool answers that one: it records the SHA-256 hash of every file in a folder, and later tells you exactly which files were added, modified, or removed.

It is a baseline tool. The first run creates a trusted snapshot; every later run compares the folder against it.

## Running it

Standard library only. Create the baseline, then verify against it:

```console
python -m src.fim ./watched --baseline baseline.json --create
python -m src.fim ./watched --baseline baseline.json
```

`--baseline` defaults to `baseline.json` in the current directory. The tool excludes its own baseline file from the comparison, so you can keep the baseline inside the folder you are watching without it appearing as a change.

## What the output looks like

A clean folder reports one line:

```
No integrity changes detected.
```

After adding a file, editing another, and deleting a third:

```
Integrity changes detected:
  ADDED    three.txt
  MODIFIED one.txt
  REMOVED  two.txt
```

Each result is one of `ADDED`, `MODIFIED` or `REMOVED`, and the path is relative to the folder you passed in.

## How it works

`build_baseline()` walks the folder, hashes each file in one-megabyte chunks so a large file does not need to fit in memory, and records the digest with the file size. `compare_baseline()` rebuilds that picture and diffs it against the stored one. Digests are compared, not timestamps, so touching a file without changing its contents is not reported as a change.

`load_baseline()` validates the file before anything is compared: it must be a JSON object, and every entry must carry a 64-character hexadecimal SHA-256 digest. A baseline saved by an editor that writes a UTF-8 byte order mark still loads, and a digest written in upper case is normalised rather than rejected, because hex is case-insensitive.

## Where it is useful, and where it is not

This is the right tool for a small folder you care about: configuration directories, a lab web root, a set of scripts you have audited. It is not a replacement for a real endpoint agent. It has no scheduler, no alerting, no signature database, and no protection against someone who edits the baseline as well as the files. Run it from a task scheduler or a cron job if you want it to run on a schedule.

## Tests

```console
python -m pytest -q tests
```

The tests cover added, modified and removed files, a baseline stored inside the watched folder, invalid baseline metadata, a byte-order-mark baseline, and upper-case digests.
