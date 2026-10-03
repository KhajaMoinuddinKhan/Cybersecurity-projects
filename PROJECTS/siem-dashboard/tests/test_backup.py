"""Backup, verification and restore of the single-file event store.

The tests build small SQLite databases directly rather than through
``app.get_connection``: this module only needs *a* database file, and a bare
connection keeps the fixtures readable. The one test that depends on WAL
semantics opens the file in WAL mode and keeps a second connection open, to
prove the snapshot is taken with the online backup API and not a file copy.
"""
import os
import sqlite3
import time
from pathlib import Path

import pytest

from src.backup import (
    backup_summary,
    create_backup,
    list_backups,
    prune_backups,
    restore_backup,
    verify_backup,
)


def _make_db(path, rows=()):
    """A small database with an ``events`` table holding ``rows``."""

    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, v TEXT)")
        for value in rows:
            connection.execute("INSERT INTO events(v) VALUES (?)", (value,))
        connection.commit()
    finally:
        connection.close()
    return Path(path)


def _values(path):
    connection = sqlite3.connect(path)
    try:
        return [row[0] for row in connection.execute("SELECT v FROM events ORDER BY id")]
    finally:
        connection.close()


def _set_age(path, mtime):
    os.utime(path, (mtime, mtime))


# --------------------------------------------------------------------------
# create_backup
# --------------------------------------------------------------------------


def test_create_backup_returns_path_size_and_timestamp(tmp_path):
    db = _make_db(tmp_path / "live.db", ["one"])
    result = create_backup(db, tmp_path / "backups")

    backup = Path(result["path"])
    assert backup.is_file()
    assert result["size_bytes"] == backup.stat().st_size > 0
    assert result["label"] is None
    # The file name carries a UTC stamp of the form YYYYMMDDTHHMMSSZ.
    assert backup.name.startswith("live-")
    stamp = backup.name.split("-")[1].split(".")[0]
    assert len(stamp) == 16 and stamp.endswith("Z") and stamp[8] == "T"


def test_create_backup_label_is_sanitised_into_the_name(tmp_path):
    db = _make_db(tmp_path / "live.db", ["one"])
    result = create_backup(db, tmp_path / "backups", label="pre upgrade / v2")
    assert result["label"] == "pre-upgrade-v2"
    assert "pre-upgrade-v2" in Path(result["path"]).name


def test_create_backup_creates_the_destination_directory(tmp_path):
    db = _make_db(tmp_path / "live.db", ["one"])
    destination = tmp_path / "does" / "not" / "exist"
    create_backup(db, destination)
    assert destination.is_dir()


def test_backup_is_a_single_file_without_sidecars(tmp_path):
    db = _make_db(tmp_path / "live.db", ["one", "two"])
    path = Path(create_backup(db, tmp_path / "backups")["path"])
    assert not Path(f"{path}-wal").exists()
    assert not Path(f"{path}-shm").exists()
    # And it reads back on its own, with the committed rows.
    report = verify_backup(path)
    assert report["ok"] is True
    assert report["tables"] == {"events": 2}


def test_snapshot_is_consistent_while_another_connection_holds_the_database(tmp_path):
    db = tmp_path / "live.db"
    writer = sqlite3.connect(db)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("CREATE TABLE events(id INTEGER PRIMARY KEY, v TEXT)")
        writer.execute("INSERT INTO events(v) VALUES ('one')")
        writer.commit()

        reader = sqlite3.connect(db)  # a second connection keeps the store open
        try:
            writer.execute("INSERT INTO events(v) VALUES ('two')")
            writer.commit()

            wal = Path(f"{db}-wal")
            assert wal.exists() and wal.stat().st_size > 0

            result = create_backup(db, tmp_path / "backups")
            report = verify_backup(result["path"])
            assert report["ok"] is True
            # Both commits are present, including the one still only in the WAL.
            assert report["tables"]["events"] == 2
        finally:
            reader.close()
    finally:
        writer.close()


def test_backup_of_a_database_with_no_rows(tmp_path):
    db = _make_db(tmp_path / "live.db")  # table, no rows
    report = verify_backup(create_backup(db, tmp_path / "backups")["path"])
    assert report["ok"] is True
    assert report["tables"] == {"events": 0}
    assert report["row_count"] == 0


def test_backup_of_a_completely_empty_database(tmp_path):
    db = tmp_path / "empty.db"
    sqlite3.connect(db).close()  # a zero-byte file: a valid, empty database

    result = create_backup(db, tmp_path / "backups")
    report = verify_backup(result["path"])
    assert report["ok"] is True
    assert report["tables"] == {}
    assert report["row_count"] == 0


def test_two_backups_in_the_same_second_do_not_collide(tmp_path):
    db = _make_db(tmp_path / "live.db", ["one"])
    first = create_backup(db, tmp_path / "backups")["path"]
    second = create_backup(db, tmp_path / "backups")["path"]
    assert first != second
    assert Path(first).is_file() and Path(second).is_file()


def test_create_backup_missing_database_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="existing file"):
        create_backup(tmp_path / "absent.db", tmp_path / "backups")


def test_create_backup_dest_dir_that_is_a_file_is_rejected(tmp_path):
    db = _make_db(tmp_path / "live.db", ["one"])
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    with pytest.raises(ValueError, match="not a directory"):
        create_backup(db, blocker)


def test_create_backup_of_a_corrupt_database_raises_and_leaves_no_file(tmp_path):
    source = _make_db(tmp_path / "source.db", ["one"])
    raw = bytearray(source.read_bytes())
    for index in range(min(100, len(raw))):
        raw[index] ^= 0xFF
    broken = tmp_path / "broken.db"
    broken.write_bytes(bytes(raw))
    directory = tmp_path / "backups"

    with pytest.raises(sqlite3.DatabaseError):
        create_backup(broken, directory)

    # The failed snapshot is not left behind pretending to be a backup.
    assert list(directory.iterdir()) == []


@pytest.mark.parametrize("bad", [5, "", "   ", "!!!"])
def test_create_backup_bad_label_is_rejected(tmp_path, bad):
    db = _make_db(tmp_path / "live.db", ["one"])
    with pytest.raises(ValueError, match="label"):
        create_backup(db, tmp_path / "backups", label=bad)


# --------------------------------------------------------------------------
# verify_backup
# --------------------------------------------------------------------------


def test_verify_reports_ok_and_row_counts(tmp_path):
    db = _make_db(tmp_path / "live.db", ["a", "b"])
    connection = sqlite3.connect(db)
    connection.execute("CREATE TABLE other(id INTEGER PRIMARY KEY)")
    connection.execute("INSERT INTO other DEFAULT VALUES")
    connection.commit()
    connection.close()

    report = verify_backup(create_backup(db, tmp_path / "backups")["path"])
    assert report["ok"] is True
    assert report["integrity"] == "ok"
    assert report["error"] is None
    assert report["tables"] == {"events": 2, "other": 1}
    assert report["row_count"] == 3


def test_verify_reports_a_truncated_file_rather_than_raising(tmp_path):
    db = _make_db(tmp_path / "live.db", ["a", "b", "c"])
    raw = Path(create_backup(db, tmp_path / "backups")["path"]).read_bytes()

    broken = tmp_path / "truncated.db"
    broken.write_bytes(raw[:100])

    report = verify_backup(broken)
    assert report["ok"] is False
    assert report["error"]
    assert report["tables"] == {}
    assert report["row_count"] == 0


def test_verify_reports_a_corrupted_file_rather_than_raising(tmp_path):
    db = _make_db(tmp_path / "live.db", ["a", "b", "c"])
    raw = bytearray(Path(create_backup(db, tmp_path / "backups")["path"]).read_bytes())
    for index in range(min(100, len(raw))):
        raw[index] ^= 0xFF

    broken = tmp_path / "corrupted.db"
    broken.write_bytes(bytes(raw))

    report = verify_backup(broken)
    assert report["ok"] is False
    assert report["error"]


def test_verify_missing_file_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="existing file"):
        verify_backup(tmp_path / "absent.db")


# --------------------------------------------------------------------------
# list_backups
# --------------------------------------------------------------------------


def test_list_backups_returns_newest_first(tmp_path):
    db = _make_db(tmp_path / "live.db", ["one"])
    directory = tmp_path / "backups"
    first = create_backup(db, directory)["path"]
    second = create_backup(db, directory)["path"]
    third = create_backup(db, directory)["path"]
    _set_age(first, 1_000)
    _set_age(second, 2_000)
    _set_age(third, 3_000)

    listed = [entry["path"] for entry in list_backups(directory)]
    assert listed == [third, second, first]
    assert all(set(entry) == {"path", "size_bytes", "created_at"} for entry in list_backups(directory))


def test_list_backups_missing_directory_is_empty(tmp_path):
    assert list_backups(tmp_path / "absent") == []


def test_list_backups_ignores_non_database_files(tmp_path):
    db = _make_db(tmp_path / "live.db", ["one"])
    directory = tmp_path / "backups"
    create_backup(db, directory)
    (directory / "notes.txt").write_text("hello", encoding="utf-8")

    assert len(list_backups(directory)) == 1


def test_list_backups_verify_adds_an_integrity_field(tmp_path):
    db = _make_db(tmp_path / "live.db", ["one"])
    directory = tmp_path / "backups"
    create_backup(db, directory)

    assert "integrity" not in list_backups(directory)[0]
    verified = list_backups(directory, verify=True)[0]
    assert verified["integrity"]["ok"] is True
    assert verified["integrity"]["tables"] == {"events": 1}


# --------------------------------------------------------------------------
# restore_backup
# --------------------------------------------------------------------------


def test_restore_refuses_to_overwrite_without_force(tmp_path):
    source = _make_db(tmp_path / "source.db", ["new"])
    backup = create_backup(source, tmp_path / "backups")["path"]
    target = _make_db(tmp_path / "target.db", ["old"])

    with pytest.raises(ValueError, match="force"):
        restore_backup(backup, target)

    # The existing database is untouched.
    assert _values(target) == ["old"]


def test_restore_with_force_makes_a_safety_copy(tmp_path):
    source = _make_db(tmp_path / "source.db", ["new"])
    backup = create_backup(source, tmp_path / "backups")["path"]
    target = _make_db(tmp_path / "target.db", ["old"])

    result = restore_backup(backup, target, force=True)

    assert result["restored"] is True
    assert result["db_path"] == str(target)
    safety = Path(result["safety_copy"])
    assert safety.is_file()
    assert safety.name.endswith(".bak")
    # The safety copy holds what was there before; the target holds the backup.
    assert _values(safety) == ["old"]
    assert _values(target) == ["new"]
    assert result["bytes_restored"] == Path(backup).stat().st_size


def test_restore_creates_the_database_when_it_is_absent(tmp_path):
    source = _make_db(tmp_path / "source.db", ["one", "two"])
    backup = create_backup(source, tmp_path / "backups")["path"]
    target = tmp_path / "fresh.db"

    result = restore_backup(backup, target)

    assert result["safety_copy"] is None
    assert result["restored"] is True
    assert _values(target) == ["one", "two"]


def test_restore_removes_stale_wal_and_shm_sidecars(tmp_path):
    source = _make_db(tmp_path / "source.db", ["new"])
    backup = create_backup(source, tmp_path / "backups")["path"]
    target = _make_db(tmp_path / "target.db", ["old"])
    Path(f"{target}-wal").write_bytes(b"")
    Path(f"{target}-shm").write_bytes(b"")

    result = restore_backup(backup, target, force=True)

    assert not Path(f"{target}-wal").exists()
    assert not Path(f"{target}-shm").exists()
    assert len(result["removed_sidecars"]) == 2


def test_restore_over_an_unreadable_database_still_makes_a_safety_copy(tmp_path):
    source = _make_db(tmp_path / "source.db", ["new"])
    backup = create_backup(source, tmp_path / "backups")["path"]

    target = _make_db(tmp_path / "target.db", ["old"])
    raw = bytearray(target.read_bytes())
    for index in range(min(100, len(raw))):
        raw[index] ^= 0xFF
    corrupt = bytes(raw)
    target.write_bytes(corrupt)

    result = restore_backup(backup, target, force=True)

    safety = Path(result["safety_copy"])
    assert safety.is_file()
    # The unreadable bytes are preserved verbatim, so the mistake is recoverable.
    assert safety.read_bytes() == corrupt
    assert _values(target) == ["new"]


def test_restore_rejects_a_corrupt_backup(tmp_path):
    source = _make_db(tmp_path / "source.db", ["new"])
    raw = bytearray(Path(create_backup(source, tmp_path / "backups")["path"]).read_bytes())
    for index in range(min(100, len(raw))):
        raw[index] ^= 0xFF
    broken = tmp_path / "broken.db"
    broken.write_bytes(bytes(raw))

    with pytest.raises(ValueError, match="integrity_check"):
        restore_backup(broken, tmp_path / "target.db")


def test_restore_onto_itself_is_rejected(tmp_path):
    source = _make_db(tmp_path / "source.db", ["new"])
    backup = create_backup(source, tmp_path / "backups")["path"]
    with pytest.raises(ValueError, match="different files"):
        restore_backup(backup, backup)


def test_restore_missing_backup_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="existing file"):
        restore_backup(tmp_path / "absent.db", tmp_path / "target.db")


# --------------------------------------------------------------------------
# prune_backups
# --------------------------------------------------------------------------


def test_prune_keeps_the_newest_and_removes_the_rest(tmp_path):
    db = _make_db(tmp_path / "live.db", ["one"])
    directory = tmp_path / "backups"
    paths = [create_backup(db, directory)["path"] for _ in range(5)]
    for index, path in enumerate(paths):
        _set_age(path, 1_000 + index)  # paths[-1] is the newest
    removed_bytes = sum(Path(path).stat().st_size for path in paths[:3])

    result = prune_backups(directory, keep=2)

    assert result["removed_count"] == 3
    assert result["kept_count"] == 2
    assert paths[-1] in result["kept"]  # the newest is never removed
    assert Path(paths[-1]).exists()
    assert sorted(result["removed"]) == sorted(paths[:3])
    assert not any(Path(path).exists() for path in paths[:3])
    assert result["freed_bytes"] == removed_bytes


def test_prune_keeps_only_the_newest_with_keep_one(tmp_path):
    db = _make_db(tmp_path / "live.db", ["one"])
    directory = tmp_path / "backups"
    paths = [create_backup(db, directory)["path"] for _ in range(3)]
    for index, path in enumerate(paths):
        _set_age(path, 1_000 + index)

    result = prune_backups(directory, keep=1)

    assert result["kept"] == [paths[-1]]
    assert Path(paths[-1]).exists()
    assert len(list_backups(directory)) == 1


def test_prune_removes_nothing_when_within_the_limit(tmp_path):
    db = _make_db(tmp_path / "live.db", ["one"])
    directory = tmp_path / "backups"
    paths = [create_backup(db, directory)["path"] for _ in range(2)]

    result = prune_backups(directory, keep=5)

    assert result["removed"] == []
    assert result["removed_count"] == 0
    assert result["kept_count"] == 2
    assert all(Path(path).exists() for path in paths)


def test_prune_on_missing_directory_removes_nothing(tmp_path):
    result = prune_backups(tmp_path / "absent", keep=7)
    assert result["removed"] == []
    assert result["kept_count"] == 0


@pytest.mark.parametrize("bad", [0, -1, True, "7", 1.5])
def test_prune_rejects_a_bad_keep_count(tmp_path, bad):
    with pytest.raises(ValueError, match="keep must be a positive integer"):
        prune_backups(tmp_path, keep=bad)


# --------------------------------------------------------------------------
# backup_summary
# --------------------------------------------------------------------------


def test_backup_summary_counts_bytes_and_age(tmp_path):
    db = _make_db(tmp_path / "live.db", ["one"])
    directory = tmp_path / "backups"
    first = create_backup(db, directory)["path"]
    second = create_backup(db, directory)["path"]
    now = int(time.time())
    _set_age(first, now - 500)
    _set_age(second, now - 100)

    summary = backup_summary(directory)

    assert summary["count"] == 2
    assert summary["total_bytes"] == Path(first).stat().st_size + Path(second).stat().st_size
    assert summary["newest"] == second
    assert 100 <= summary["newest_age_seconds"] <= 110


def test_backup_summary_of_empty_directory(tmp_path):
    summary = backup_summary(tmp_path / "absent")
    assert summary == {"count": 0, "total_bytes": 0, "newest": None, "newest_age_seconds": None}
