"""Create and compare SHA-256 file-integrity baselines."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


# [SECTION] Hashing configuration
# Reading large files in chunks avoids loading an entire file into memory at once.
CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path) -> str:
    """Calculate the SHA-256 digest of a file using memory-friendly chunks."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


# [SECTION] Baseline creation
def build_baseline(folder: Path) -> dict[str, dict[str, Any]]:
    """Create a deterministic baseline of file hashes and sizes under a folder."""

    folder = folder.resolve()
    baseline: dict[str, dict[str, Any]] = {}

    # rglob walks the directory recursively; sorting keeps output stable between runs.
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            relative_path = path.relative_to(folder).as_posix()
            baseline[relative_path] = {
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
    return baseline


def save_baseline(
    baseline: dict[str, dict[str, Any]], destination: Path
) -> None:
    """Save the baseline as readable, consistently ordered JSON."""

    destination.write_text(
        json.dumps(baseline, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def load_baseline(path: Path) -> dict[str, dict[str, Any]]:
    """Load a saved JSON baseline and verify its top-level structure."""

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Baseline must contain a JSON object.")
    return data


# [SECTION] Integrity comparison
def compare_baseline(
    folder: Path, baseline: dict[str, dict[str, Any]]
) -> list[tuple[str, str]]:
    """Classify files as added, modified, or removed compared with a baseline."""

    current = build_baseline(folder)
    changes: list[tuple[str, str]] = []

    # Files present now may be new or may have changed content.
    for path, metadata in current.items():
        if path not in baseline:
            changes.append(("ADDED", path))
        elif baseline[path].get("sha256") != metadata["sha256"]:
            changes.append(("MODIFIED", path))

    # Files that existed in the baseline but no longer exist are removals.
    for path in baseline:
        if path not in current:
            changes.append(("REMOVED", path))

    return sorted(changes)


# [SECTION] Command-line interface
def main() -> None:
    """Create a baseline or compare a folder against an existing one."""

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
        save_baseline(build_baseline(args.folder), args.baseline)
        print("Baseline created.")
        return

    if not args.baseline.is_file():
        raise SystemExit("Baseline not found. Use --create first.")

    changes = compare_baseline(args.folder, load_baseline(args.baseline))
    if not changes:
        print("No integrity changes detected.")
        return

    print("Integrity changes detected:")
    for kind, path in changes:
        print(f"  {kind:8} {path}")


if __name__ == "__main__":
    main()
