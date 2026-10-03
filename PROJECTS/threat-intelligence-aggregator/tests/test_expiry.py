"""Stale indicators are pruned and the pruning is reported."""
from datetime import datetime, timezone

from src.aggregator import (
    expire_iocs,
    import_indicators,
    list_indicators,
)

NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)


def _seed(db):
    import_indicators(
        db, [("ip", "198.51.100.23", "feed-a")], now=datetime(2026, 1, 1, tzinfo=timezone.utc)
    )
    import_indicators(
        db,
        [("domain", "fresh.example", "feed-a")],
        now=datetime(2026, 9, 30, tzinfo=timezone.utc),
    )


def test_expire_prunes_only_indicators_older_than_the_window(tmp_path):
    db = tmp_path / "intel.db"
    _seed(db)

    pruned = expire_iocs(db, 30, now=NOW)

    assert [(item.type, item.value) for item in pruned] == [("ip", "198.51.100.23")]
    remaining = [hit.value for hit in list_indicators(db, now=NOW)]
    assert remaining == ["fresh.example"]


def test_expire_removes_the_source_history_too(tmp_path):
    db = tmp_path / "intel.db"
    _seed(db)
    expire_iocs(db, 30, now=NOW)

    from src.aggregator import collect_stats

    stats = collect_stats(db, now=NOW)
    assert stats.total == 1
    assert dict(stats.by_source) == {"feed-a": 1}


def test_expire_reports_nothing_when_everything_is_fresh(tmp_path):
    db = tmp_path / "intel.db"
    import_indicators(db, [("ip", "8.8.8.8", "feed-a")], now=NOW)
    assert expire_iocs(db, 30, now=NOW) == []
