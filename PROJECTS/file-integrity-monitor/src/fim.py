"""Track file changes with SHA-256 hashes."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

# Read large files in chunks instead of loading them all at once.
CHUNK_SIZE = 1024 * 1024

def sha256_file(path: Path) -> str:
    """Calculate a file's SHA-256 hash."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()

def files_under(folder: Path) -> list[Path]:
    """Return every file under a folder without walking a directory twice.

    ``rglob`` follows a Windows junction because a junction is not reported as a
    symlink, so a junction that points at one of its own ancestors would repeat
    the same files under ever-longer paths. Tracking the resolved ancestor chain
    keeps the walk finite without changing which links are followed.
    """

    found: list[Path] = []

    def walk(directory: Path, ancestors: frozenset[Path]) -> None:
        real = directory.resolve()
        if real in ancestors:
            return
        ancestors = ancestors | {real}
        for entry in sorted(directory.iterdir()):
            if entry.is_dir() and not entry.is_symlink():
                walk(entry, ancestors)
            elif entry.is_file():
                found.append(entry)

    walk(folder, frozenset())
    return found


def build_baseline(folder: Path, *, exclude: Path | None = None) -> dict[str, dict[str, Any]]:
    """Build a baseline for every file in a folder."""

    folder = folder.resolve()
    excluded = exclude.resolve() if exclude is not None else None
    baseline: dict[str, dict[str, Any]] = {}

    # Sorting keeps the saved baseline in a stable order.
    for path in sorted(files_under(folder)):
        if path.resolve() != excluded:
            relative_path = path.relative_to(folder).as_posix()
            baseline[relative_path] = {
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
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

def compare_baseline(
    folder: Path, baseline: dict[str, dict[str, Any]], *, exclude: Path | None = None
) -> list[tuple[str, str]]:
    """Find files that were added, changed, or removed."""

    current = build_baseline(folder, exclude=exclude)
    if exclude is not None:
        excluded = exclude.resolve()
        baseline = {name: metadata for name, metadata in baseline.items() if (folder / name).resolve() != excluded}
    changes: list[tuple[str, str]] = []

    for path, metadata in current.items():
        if path not in baseline:
            changes.append(("ADDED", path))
        elif baseline[path].get("sha256") != metadata["sha256"]:
            changes.append(("MODIFIED", path))

    for path in baseline:
        if path not in current:
            changes.append(("REMOVED", path))

    return sorted(changes)

def main() -> None:
    """Create a baseline or compare against one."""

    parser = argparse.ArgumentParser(
        description="Monitor files with a SHA-256 baseline."
    )
    parser.add_argument("folder", type=Path)
    parser.add_argument("--baseline", type=Path, default=Path("baseline.json"))
    parser.add_argument("--create", action="store_true")
    args = parser.parse_args()

    if not args.folder.is_dir():
        raise SystemExit(f"Folder not found: {args.folder}")

    if args.create:
        save_baseline(build_baseline(args.folder, exclude=args.baseline), args.baseline)
        print("Baseline created.")
        return

    if not args.baseline.is_file():
        raise SystemExit("Baseline not found. Use --create first.")

    changes = compare_baseline(args.folder, load_baseline(args.baseline), exclude=args.baseline)
    if not changes:
        print("No integrity changes detected.")
        return

    print("Integrity changes detected:")
    for kind, path in changes:
        print(f"  {kind:8} {path}")

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        raise SystemExit(f"File integrity check failed: {exc}") from exc
