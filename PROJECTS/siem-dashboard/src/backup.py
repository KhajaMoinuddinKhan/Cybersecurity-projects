"""Backup, verification and restore for the single-file event store.

The console keeps all of its state -- events, accounts, hosts, triage and the
audit log -- in one SQLite database opened in WAL mode (see
``app.get_connection``). The README lists the absence of backup as a gap, and
this module is the answer to it. It is deliberately a *file-level* tool: it
takes a point-in-time snapshot of one database file, checks a snapshot, and
puts a snapshot back. It is not replication and it is not high availability.

Snapshots are taken with :meth:`sqlite3.Connection.backup`, SQLite's online
backup API, rather than by copying the file. That matters because the store
runs in WAL mode: committed transactions can be sitting in the ``-wal`` file
and not yet in the main database, so a plain byte copy of the ``.db`` file can
silently miss recent commits. The online backup API reads a consistent snapshot
of the logical database -- including committed WAL frames -- while the server
keeps writing. The snapshot is written as a single self-contained file: its
write-ahead log is checkpointed and the sidecar is removed, so a backup has no
``-wal``/``-shm`` of its own to keep beside it. No committed data is lost by
that checkpoint; the frames it folds in are already part of the snapshot.

What this module is not
-----------------------
* **Not replication and not high availability.** A backup is a copy, not a
  second server. There is no failover, no streaming and no standby. If the host
  is lost, everything written since the last snapshot is lost.
* **A restore needs the server stopped.** SQLite does not support overwriting a
  database that another connection has open. :func:`restore_backup` is meant to
  run against a stopped console; against a running one the final file replace
  can fail, and even if it succeeded the running process would still be holding
  the old database. Stop the process that owns the database first.
* **Not encrypted.** Backups are ordinary SQLite files written to ``dest_dir``
  and are protected only by the filesystem's permissions. This module adds no
  encryption, so a backup holds the same sensitive events as the store itself.
* **Not shipped off the host.** Files are written to the directory you name;
  moving them somewhere else is left to the operator.

The backup directory is expected to be dedicated. :func:`list_backups`,
:func:`prune_backups` and :func:`backup_summary` treat every ``*.db`` file in
the directory as a backup, so pointing them at the directory that holds the
live database would list, and could prune, the live database itself.
"""
from __future__ import annotations

import os
import re
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# The compact UTC stamp that names a backup file, e.g. ``20260104T153045Z``.
_STAMP_FORMAT = "%Y%m%dT%H%M%SZ"

# The same UTC instant in the space-separated form the rest of the console
# stores timestamps in, used for the ``created_at`` fields.
_READABLE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Backup files are ordinary SQLite databases with this suffix.
_SUFFIX = ".db"

# Sidecar files that belong to a database and must not outlive it.
_SIDECARS = ("-wal", "-shm")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_path(value: Any, field: str) -> Path:
    """Coerce ``value`` to a Path, rejecting anything that is not a path."""

    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty path string")
    return Path(value)


def _require_file(value: Any, field: str) -> Path:
    path = _require_path(value, field)
    if not path.is_file():
        raise ValueError(f"{field} must be an existing file: {path}")
    return path


def _clean_label(label: Any) -> str | None:
    """Validate and sanitise an optional backup label for use in a file name."""

    if label is None:
        return None
    if not isinstance(label, str):
        raise ValueError("label must be a string or None")
    text = label.strip()
    if not text:
        raise ValueError("label must be a non-empty string")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-.")
    if not safe:
        raise ValueError("label must contain at least one letter, digit, dot, dash or underscore")
    return safe[:64]


def _readonly_uri(path: Path) -> str:
    """A ``mode=ro`` URI so a backup is never modified while it is checked."""

    return Path(path).resolve().as_uri() + "?mode=ro"


def _snapshot(source_path: Path, dest_path: Path) -> None:
    """Write a consistent snapshot of ``source_path`` to ``dest_path``.

    Uses the online backup API, so committed WAL frames are included and the
    copy stays consistent even while another connection writes. The
    destination is checkpointed and its sidecars removed so the result is one
    self-contained file.
    """

    source = sqlite3.connect(str(source_path))
    try:
        destination = sqlite3.connect(str(dest_path))
        try:
            source.backup(destination)
            destination.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except BaseException:
            # A half-written destination must not be left looking like a backup.
            destination.close()
            for suffix in ("", *_SIDECARS):
                partial = Path(f"{dest_path}{suffix}")
                if partial.exists():
                    partial.unlink()
            raise
        destination.close()
    finally:
        source.close()
    for suffix in _SIDECARS:
        sidecar = Path(f"{dest_path}{suffix}")
        if sidecar.exists():
            sidecar.unlink()


def _unique_path(directory: Path, stem: str, suffix: str = _SUFFIX) -> Path:
    """A name that does not collide with an existing file."""

    candidate = directory / f"{stem}{suffix}"
    counter = 1
    while candidate.exists():
        candidate = directory / f"{stem}-{counter}{suffix}"
        counter += 1
    return candidate


def create_backup(db_path: Any, dest_dir: Any, label: str | None = None) -> dict[str, Any]:
    """Take a consistent snapshot of a live database into ``dest_dir``.

    ``db_path`` must be an existing SQLite file. ``dest_dir`` is created if it
    does not exist. The snapshot is written with
    :meth:`sqlite3.Connection.backup`, so it is a consistent point-in-time copy
    even while the console holds the database open and writes to it -- a plain
    file copy would not be. The file is named
    ``<database>-<UTC stamp>[-<label>].db`` and has no ``-wal``/``-shm`` of its
    own.

    Returns ``path`` (the new file), ``size_bytes``, ``created_at`` (UTC) and
    the sanitised ``label`` (or ``None``). Raises ``ValueError`` if ``db_path``
    is missing, ``dest_dir`` exists and is not a directory, or ``label`` is not
    a usable string.
    """

    source = _require_file(db_path, "db_path")
    directory = _require_path(dest_dir, "dest_dir")
    if directory.exists() and not directory.is_dir():
        raise ValueError(f"dest_dir exists and is not a directory: {directory}")
    directory.mkdir(parents=True, exist_ok=True)

    clean_label = _clean_label(label)
    now = _utc_now()
    stem = f"{source.stem or 'backup'}-{now.strftime(_STAMP_FORMAT)}"
    if clean_label:
        stem = f"{stem}-{clean_label}"
    destination = _unique_path(directory, stem)

    _snapshot(source, destination)
    return {
        "path": str(destination),
        "size_bytes": destination.stat().st_size,
        "created_at": now.strftime(_READABLE_FORMAT),
        "label": clean_label,
    }


def list_backups(dest_dir: Any, verify: bool = False) -> list[dict[str, Any]]:
    """List the backups in ``dest_dir``, newest first.

    Each entry has ``path``, ``size_bytes`` and ``created_at`` (UTC). When
    ``verify`` is true each entry also carries an ``integrity`` field holding
    the :func:`verify_backup` result; it is absent otherwise so listing does
    not pay for reading every file.

    A missing directory lists as empty. Every ``*.db`` file in the directory is
    treated as a backup, so keep backups in a directory of their own.
    """

    directory = _require_path(dest_dir, "dest_dir")
    if not directory.is_dir():
        return []

    found: list[tuple[int, str, dict[str, Any]]] = []
    for item in directory.iterdir():
        if not item.is_file() or item.suffix.lower() != _SUFFIX:
            continue
        stat = item.stat()
        entry: dict[str, Any] = {
            "path": str(item),
            "size_bytes": int(stat.st_size),
            "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime(
                _READABLE_FORMAT
            ),
        }
        if verify:
            entry["integrity"] = verify_backup(item)
        found.append((stat.st_mtime_ns, item.name, entry))

    found.sort(key=lambda row: (row[0], row[1]), reverse=True)
    return [row[2] for row in found]


def verify_backup(path: Any) -> dict[str, Any]:
    """Check a backup and report what it holds, without raising on damage.

    Opens the file read-only, runs ``PRAGMA integrity_check`` and counts the
    rows in every table it finds. A truncated or corrupted file is reported as
    ``ok`` false with the SQLite error in ``integrity`` and ``error``; it is
    never trusted and the call does not raise for it. ``ValueError`` is raised
    only when ``path`` is not an existing file.

    Returns ``path``, ``ok``, ``integrity`` (``"ok"`` or the problem text),
    ``tables`` (name -> row count), ``row_count`` (the total) and ``error``.
    ``integrity_check`` reads the whole database, so this is not free on a
    large file.
    """

    target = _require_file(path, "path")
    report: dict[str, Any] = {
        "path": str(target),
        "ok": False,
        "integrity": "",
        "tables": {},
        "row_count": 0,
        "error": None,
    }

    try:
        connection = sqlite3.connect(_readonly_uri(target), uri=True)
    except sqlite3.Error as exc:  # pragma: no cover - open rarely fails on a file we stat'd
        report["integrity"] = str(exc)
        report["error"] = str(exc)
        return report

    try:
        findings = [str(row[0]) for row in connection.execute("PRAGMA integrity_check").fetchall()]
        if findings != ["ok"]:
            problem = "; ".join(findings) or "integrity_check returned no result"
            report["integrity"] = problem
            report["error"] = problem
            return report

        names = [
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        tables: dict[str, int] = {}
        for name in names:
            quoted = name.replace('"', '""')
            tables[name] = int(connection.execute(f'SELECT COUNT(*) FROM "{quoted}"').fetchone()[0])
        report["tables"] = tables
        report["row_count"] = sum(tables.values())
        report["integrity"] = "ok"
        report["ok"] = True
    except sqlite3.Error as exc:
        report["tables"] = {}
        report["row_count"] = 0
        report["integrity"] = str(exc)
        report["error"] = str(exc)
    finally:
        connection.close()
    return report


def _safety_copy(db_path: Path, directory: Path) -> Path:
    """Preserve the current database before it is overwritten.

    Prefers a consistent online-backup snapshot; if the current database cannot
    be read by SQLite at all, falls back to a raw byte copy so the file the
    operator is about to replace is still recoverable.
    """

    stamp = _utc_now().strftime(_STAMP_FORMAT)
    base = f"{db_path.name}.pre-restore-{stamp}"
    target = _unique_path(directory, base, ".bak")
    try:
        _snapshot(db_path, target)
    except sqlite3.Error:
        shutil.copy2(db_path, target)
    return target


def restore_backup(backup_path: Any, db_path: Any, force: bool = False) -> dict[str, Any]:
    """Put a backup back, refusing to clobber an existing database by default.

    What it does to the current database, step by step:

    1. Verifies the backup with :func:`verify_backup` and refuses to restore
       from a file that fails, so a corrupt snapshot cannot replace good data.
    2. If ``db_path`` exists and ``force`` is false, raises ``ValueError`` and
       touches nothing.
    3. If ``db_path`` exists and ``force`` is true, takes a safety copy first,
       named ``<database>.pre-restore-<UTC stamp>.bak`` in the database's own
       directory. That copy uses the online backup API, so it is a consistent
       snapshot; if the current file is unreadable it falls back to a byte
       copy. A mistaken restore is therefore recoverable.
    4. Removes the existing ``-wal`` and ``-shm`` sidecars of ``db_path``. They
       belong to the database being replaced; replaying them against the
       restored file would corrupt it.
    5. Copies the backup to a temporary file in the same directory and
       ``os.replace``s it onto ``db_path``, so the target is swapped in one
       step rather than left half-written.

    Because SQLite will not let a live connection's database be overwritten
    underneath it, run this with the console stopped; a running process can
    make the final replace fail and would in any case still be holding the old
    database.

    Returns ``restored``, ``db_path``, ``backup_path``, ``safety_copy`` (or
    ``None`` when there was nothing to preserve), ``bytes_restored`` and
    ``removed_sidecars``.
    """

    backup = _require_file(backup_path, "backup_path")
    target = _require_path(db_path, "db_path")
    if target.exists() and not target.is_file():
        raise ValueError(f"db_path exists and is not a file: {target}")
    if backup.resolve() == target.resolve():
        raise ValueError("backup_path and db_path must be different files")

    report = verify_backup(backup)
    if not report["ok"]:
        raise ValueError(
            f"refusing to restore from a backup that fails integrity_check: {report['integrity']}"
        )

    existed = target.exists()
    if existed and not force:
        raise ValueError(
            f"{target} already exists; pass force=True to overwrite it "
            "(a safety copy is taken first)"
        )

    target.parent.mkdir(parents=True, exist_ok=True)

    safety: Path | None = None
    if existed:
        safety = _safety_copy(target, target.parent)

    removed_sidecars: list[str] = []
    for suffix in _SIDECARS:
        sidecar = Path(f"{target}{suffix}")
        if sidecar.exists():
            sidecar.unlink()
            removed_sidecars.append(str(sidecar))

    temporary = target.parent / f".{target.name}.restore-{os.getpid()}.tmp"
    try:
        shutil.copyfile(backup, temporary)
        try:
            os.replace(temporary, target)
        except OSError as exc:
            raise ValueError(
                f"could not replace {target}: {exc}; stop the console that owns "
                "the database before restoring"
            ) from exc
    finally:
        if temporary.exists():
            temporary.unlink()

    return {
        "restored": True,
        "db_path": str(target),
        "backup_path": str(backup),
        "safety_copy": str(safety) if safety is not None else None,
        "bytes_restored": backup.stat().st_size,
        "removed_sidecars": removed_sidecars,
    }


def prune_backups(dest_dir: Any, keep: int = 7) -> dict[str, Any]:
    """Remove all but the ``keep`` newest backups in ``dest_dir``.

    ``keep`` must be a positive integer, so at least the newest backup is
    always retained. Returns ``removed`` and ``kept`` (paths), their counts,
    and ``freed_bytes``.
    """

    if isinstance(keep, bool) or not isinstance(keep, int) or keep < 1:
        raise ValueError("keep must be a positive integer")

    backups = list_backups(dest_dir)
    kept = [entry["path"] for entry in backups[:keep]]
    removed: list[str] = []
    freed = 0
    for entry in backups[keep:]:
        path = Path(entry["path"])
        freed += int(entry["size_bytes"])
        path.unlink()
        removed.append(entry["path"])
    return {
        "removed": removed,
        "removed_count": len(removed),
        "kept": kept,
        "kept_count": len(kept),
        "freed_bytes": freed,
    }


def backup_summary(dest_dir: Any) -> dict[str, Any]:
    """Summarise a backup directory: count, total size and newest age.

    ``newest_age_seconds`` is how long ago the newest backup was written, or
    ``None`` when the directory holds no backups.
    """

    backups = list_backups(dest_dir)
    total = sum(int(entry["size_bytes"]) for entry in backups)
    newest = backups[0] if backups else None
    age: int | None = None
    if newest is not None:
        written = Path(newest["path"]).stat().st_mtime
        age = max(0, int(_utc_now().timestamp() - written))
    return {
        "count": len(backups),
        "total_bytes": total,
        "newest": newest["path"] if newest is not None else None,
        "newest_age_seconds": age,
    }
