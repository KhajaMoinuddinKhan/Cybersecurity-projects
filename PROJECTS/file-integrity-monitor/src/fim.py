"""Track file changes with SHA-256 hashes and recorded metadata."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

# Read large files in chunks instead of loading them all at once.
CHUNK_SIZE = 1024 * 1024

# The kinds of change a scan can report. ADDED, MODIFIED and REMOVED describe a
# file's presence or content; PERMISSIONS is a metadata change on a file whose
# bytes did not move, so a chmod is still reported.
ADDED = "ADDED"
MODIFIED = "MODIFIED"
REMOVED = "REMOVED"
PERMISSIONS = "PERMISSIONS"
CHANGE_KINDS = (ADDED, MODIFIED, REMOVED, PERMISSIONS)

# Paths that would otherwise fill a report without telling you anything: cache
# directories and the temporary files editors leave behind. These apply to every
# scan; --exclude adds to them rather than replacing them.
DEFAULT_EXCLUDES = (
    "__pycache__",
    "*.py[cod]",
    ".git",
    ".hg",
    ".svn",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".DS_Store",
    "Thumbs.db",
    "*.swp",
    "*.swo",
    "*.tmp",
    "*~",
    ".#*",
    "#*#",
)


def sha256_file(path: Path) -> str:
    """Calculate a file's SHA-256 hash."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_excluded(relative_path: str, patterns: Sequence[str]) -> bool:
    """Report whether a relative path matches any exclude pattern.

    A pattern is matched against the whole relative path and against every
    single path component, so ``*.pyc`` skips a compiled file anywhere in the
    tree and ``build`` skips that directory and everything below it.
    """

    parts = relative_path.split("/")
    for pattern in patterns:
        if any(fnmatch.fnmatchcase(part, pattern) for part in parts):
            return True
        if fnmatch.fnmatchcase(relative_path, pattern):
            return True
    return False


def files_under(folder: Path, patterns: Sequence[str] = ()) -> list[Path]:
    """Return every file under a folder without walking a directory twice.

    ``rglob`` follows a Windows junction because a junction is not reported as a
    symlink, so a junction that points at one of its own ancestors would repeat
    the same files under ever-longer paths. Tracking the resolved ancestor chain
    keeps the walk finite without changing which links are followed. An excluded
    directory is skipped before it is entered, so its whole subtree is left out.
    """

    folder = folder.resolve()
    effective = (*DEFAULT_EXCLUDES, *patterns)
    found: list[Path] = []

    def walk(directory: Path, ancestors: frozenset[Path]) -> None:
        real = directory.resolve()
        if real in ancestors:
            return
        ancestors = ancestors | {real}
        for entry in sorted(directory.iterdir()):
            if is_excluded(entry.relative_to(folder).as_posix(), effective):
                continue
            if entry.is_dir() and not entry.is_symlink():
                walk(entry, ancestors)
            elif entry.is_file():
                found.append(entry)

    walk(folder, frozenset())
    return found


def file_metadata(path: Path) -> dict[str, Any]:
    """Record a file's digest and the metadata a later scan compares."""

    stat = path.stat()
    return {
        "sha256": sha256_file(path),
        "size": stat.st_size,
        "mtime": stat.st_mtime,
        "mode": stat.st_mode,
    }


def build_baseline(
    folder: Path, *, exclude: Path | None = None, patterns: Sequence[str] = ()
) -> dict[str, dict[str, Any]]:
    """Build a baseline for every file in a folder."""

    folder = folder.resolve()
    excluded = exclude.resolve() if exclude is not None else None
    baseline: dict[str, dict[str, Any]] = {}

    # Sorting keeps the saved baseline in a stable order.
    for path in sorted(files_under(folder, patterns)):
        if path.resolve() != excluded:
            relative_path = path.relative_to(folder).as_posix()
            baseline[relative_path] = file_metadata(path)
    return baseline


def save_baseline(
    baseline: dict[str, dict[str, Any]], destination: Path
) -> None:
    """Save the baseline as JSON."""

    destination.write_text(
        json.dumps(baseline, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def load_baseline(path: Path) -> dict[str, dict[str, Any]]:
    """Load a saved baseline."""

    # utf-8-sig accepts a baseline that an editor saved with a byte order mark.
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("Baseline must contain a JSON object.")
    for name, metadata in data.items():
        if not isinstance(metadata, dict) or not isinstance(metadata.get("sha256"), str) or not re.fullmatch(r"[0-9a-fA-F]{64}", metadata["sha256"]):
            raise ValueError(f"Invalid baseline metadata for {name!r}: expected a SHA-256 digest.")
        # Hex digests are case-insensitive, so store one case for comparison.
        metadata["sha256"] = metadata["sha256"].lower()
    return data


def compare_metadata(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """List the recorded metadata fields whose values differ.

    The content digest is compared separately and is not listed here. A field
    that an older baseline never recorded is skipped rather than treated as a
    change, so baselines written before metadata was tracked still compare.
    """

    return [field for field in ("size", "mtime", "mode") if field in old and old[field] != new[field]]


@dataclass(frozen=True)
class Change:
    """One difference between a folder and its baseline."""

    kind: str
    path: str
    detail: str = ""


def diff(
    current: dict[str, dict[str, Any]], baseline: dict[str, dict[str, Any]]
) -> list[Change]:
    """Compare a fresh inventory with a baseline and return sorted changes."""

    changes: list[Change] = []

    for path, metadata in current.items():
        if path not in baseline:
            changes.append(Change(ADDED, path))
            continue
        old = baseline[path]
        if old.get("sha256") != metadata["sha256"]:
            fields = compare_metadata(old, metadata)
            changes.append(Change(MODIFIED, path, ", ".join(fields) if fields else "content"))
        elif "mode" in old and old["mode"] != metadata["mode"]:
            # Content is identical, so only the permissions moved.
            changes.append(Change(PERMISSIONS, path, f"{oct(int(old['mode']))} -> {oct(int(metadata['mode']))}"))

    for path in baseline:
        if path not in current:
            changes.append(Change(REMOVED, path))

    return sorted(changes, key=lambda change: (change.kind, change.path))


def _drop_excluded(
    baseline: dict[str, dict[str, Any]], folder: Path, exclude: Path | None
) -> dict[str, dict[str, Any]]:
    """Remove the baseline file itself from a loaded baseline."""

    if exclude is None:
        return dict(baseline)
    excluded = exclude.resolve()
    return {name: metadata for name, metadata in baseline.items() if (folder / name).resolve() != excluded}


def scan(
    folder: Path,
    baseline: dict[str, dict[str, Any]],
    *,
    exclude: Path | None = None,
    patterns: Sequence[str] = (),
) -> list[Change]:
    """Compare a folder with a baseline and return the changes with detail."""

    current = build_baseline(folder, exclude=exclude, patterns=patterns)
    return diff(current, _drop_excluded(baseline, folder, exclude))


def compare_baseline(
    folder: Path,
    baseline: dict[str, dict[str, Any]],
    *,
    exclude: Path | None = None,
    patterns: Sequence[str] = (),
) -> list[tuple[str, str]]:
    """Find files that were added, changed, or removed."""

    return [(change.kind, change.path) for change in scan(folder, baseline, exclude=exclude, patterns=patterns)]


def summary_counts(changes: Sequence[Change]) -> dict[str, int]:
    """Count the changes of each kind, including the kinds with none."""

    counts = Counter(change.kind for change in changes)
    return {kind: counts.get(kind, 0) for kind in CHANGE_KINDS}


def format_summary(changes: Sequence[Change]) -> str:
    """One line of counts by change type."""

    counts = summary_counts(changes)
    parts = [f"{counts[kind]} {kind.lower()}" for kind in CHANGE_KINDS if counts[kind]]
    return "Summary: " + ", ".join(parts) if parts else "Summary: no changes"


def format_text(changes: Sequence[Change]) -> str:
    """Render changes as the plain-text report."""

    if not changes:
        return "No integrity changes detected."
    lines = ["Integrity changes detected:"]
    for change in changes:
        detail = f" ({change.detail})" if change.detail else ""
        lines.append(f"  {change.kind:11} {change.path}{detail}")
    lines.append(format_summary(changes))
    return "\n".join(lines)


def format_json(changes: Sequence[Change]) -> str:
    """Render changes as a JSON report."""

    payload = {
        "changes": [
            {"type": change.kind, "path": change.path, "detail": change.detail}
            for change in changes
        ],
        "summary": summary_counts(changes),
        "total": len(changes),
    }
    return json.dumps(payload, indent=2)


def watch_scans(
    folder: Path,
    baseline: dict[str, dict[str, Any]],
    *,
    interval: float,
    count: int | None,
    exclude: Path | None = None,
    patterns: Sequence[str] = (),
    sleep: Any = time.sleep,
) -> Iterator[list[Change]]:
    """Yield one list of changes per scan, sleeping between scans.

    The first scan compares against ``baseline``; every later scan compares
    against the previous scan, so a change is reported once when it appears
    instead of on every interval. ``count`` limits the number of scans, which is
    what makes the loop scriptable and testable.
    """

    reference = _drop_excluded(baseline, folder, exclude)
    scans = 0
    while count is None or scans < count:
        if scans:
            sleep(interval)
        current = build_baseline(folder, exclude=exclude, patterns=patterns)
        yield diff(current, reference)
        reference = current
        scans += 1


def watch_command(
    folder: Path,
    baseline: dict[str, dict[str, Any]],
    *,
    interval: float,
    count: int | None,
    exclude: Path | None,
    patterns: Sequence[str],
    as_json: bool,
) -> int:
    """Run watch mode and return a non-zero code if any change was seen."""

    stops = f", stopping after {count} scan{'s' if count != 1 else ''}" if count is not None else ""
    print(f"Watching {folder} every {interval:g}s{stops}.")
    total = 0
    for index, changes in enumerate(
        watch_scans(folder, baseline, interval=interval, count=count, exclude=exclude, patterns=patterns),
        start=1,
    ):
        total += len(changes)
        if as_json:
            payload = {
                "scan": index,
                "changes": [
                    {"type": change.kind, "path": change.path, "detail": change.detail}
                    for change in changes
                ],
                "summary": summary_counts(changes),
                "total": len(changes),
            }
            print(json.dumps(payload))
        else:
            number = len(changes)
            print(f"Scan {index}: {number} change{'s' if number != 1 else ''}")
            for change in changes:
                detail = f" ({change.detail})" if change.detail else ""
                print(f"  {change.kind:11} {change.path}{detail}")
    return 1 if total else 0


def main(argv: Sequence[str] | None = None) -> int:
    """Create a baseline, compare against one, or watch for changes."""

    parser = argparse.ArgumentParser(
        description="Monitor files with a SHA-256 baseline."
    )
    parser.add_argument("folder", type=Path)
    parser.add_argument("--baseline", type=Path, default=Path("baseline.json"))
    parser.add_argument("--create", action="store_true", help="write a new baseline instead of comparing")
    parser.add_argument("--watch", action="store_true", help="re-scan on an interval and print new changes")
    parser.add_argument("--interval", type=float, default=5.0, help="seconds between watch scans (default: 5)")
    parser.add_argument("--count", type=int, default=None, help="stop watch mode after this many scans")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="extra glob to skip; repeatable")
    parser.add_argument("--json", action="store_true", dest="as_json", help="print the report as JSON")
    parser.add_argument("--report", type=Path, default=None, help="also write the report to this file")
    args = parser.parse_args(argv)

    if not args.folder.is_dir():
        raise SystemExit(f"Folder not found: {args.folder}")
    if args.interval <= 0:
        raise SystemExit("--interval must be greater than zero.")
    if args.count is not None and args.count < 1:
        raise SystemExit("--count must be at least 1.")
    if args.watch and args.create:
        raise SystemExit("--create cannot be combined with --watch.")
    if args.watch and args.report is not None:
        raise SystemExit("--report cannot be combined with --watch.")

    if args.create:
        save_baseline(build_baseline(args.folder, exclude=args.baseline, patterns=args.exclude), args.baseline)
        print("Baseline created.")
        return 0

    if not args.baseline.is_file():
        raise SystemExit("Baseline not found. Use --create first.")

    baseline = load_baseline(args.baseline)

    if args.watch:
        return watch_command(
            args.folder,
            baseline,
            interval=args.interval,
            count=args.count,
            exclude=args.baseline,
            patterns=args.exclude,
            as_json=args.as_json,
        )

    changes = scan(args.folder, baseline, exclude=args.baseline, patterns=args.exclude)
    report = format_json(changes) if args.as_json else format_text(changes)
    print(report)
    if args.report is not None:
        args.report.write_text(report + "\n", encoding="utf-8")
    return 1 if changes else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        raise SystemExit(f"File integrity check failed: {exc}") from exc
