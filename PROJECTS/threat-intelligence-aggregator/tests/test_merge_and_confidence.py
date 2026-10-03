"""De-duplication across sources and the confidence it feeds."""
from datetime import datetime, timedelta, timezone

from src.aggregator import (
    compute_confidence,
    import_indicators,
    search_indicators,
)

NOW = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)


def test_same_indicator_from_two_sources_is_one_record(tmp_path):
    db = tmp_path / "intel.db"
    first = import_indicators(db, [("ip", "198.51.100.23", "feed-a")], now=NOW)
    second = import_indicators(db, [("ip", "198.51.100.23", "feed-b")], now=NOW)

    assert (first.new, second.new) == (1, 0)
    assert second.updated == 1

    hits = search_indicators(db, "198.51.100.23", now=NOW)
    assert len(hits) == 1
    assert hits[0].sources == ["feed-a", "feed-b"]
    assert hits[0].observations == 2
    # The first source that reported the indicator stays on the record.
    assert hits[0].source == "feed-a"


def test_reimporting_a_feed_updates_instead_of_duplicating(tmp_path):
    db = tmp_path / "intel.db"
    rows = [("domain", "bad.example", "feed-a")]
    assert import_indicators(db, rows, now=NOW).new == 1
    again = import_indicators(db, rows, now=NOW)
    assert (again.new, again.updated) == (0, 1)
    assert search_indicators(db, "bad.example", now=NOW)[0].observations == 2


def test_first_and_last_seen_track_each_report(tmp_path):
    db = tmp_path / "intel.db"
    early = datetime(2026, 1, 1, tzinfo=timezone.utc)
    late = datetime(2026, 2, 1, tzinfo=timezone.utc)
    import_indicators(db, [("domain", "evil.example", "feed-a")], now=early)
    import_indicators(db, [("domain", "evil.example", "feed-b")], now=late)

    hit = search_indicators(db, "evil.example", now=late)[0]
    assert hit.first_seen == "2026-01-01T00:00:00Z"
    assert hit.last_seen == "2026-02-01T00:00:00Z"


def test_confidence_rises_with_independent_sources():
    fresh = NOW
    assert compute_confidence(1, fresh, NOW) == 0.6
    assert compute_confidence(2, fresh, NOW) == 0.8
    assert compute_confidence(3, fresh, NOW) == 1.0
    # More than the target number of sources does not exceed the maximum.
    assert compute_confidence(5, fresh, NOW) == 1.0


def test_confidence_decays_as_an_indicator_ages():
    fifteen = NOW - timedelta(days=15)
    thirty = NOW - timedelta(days=30)
    assert compute_confidence(1, fifteen, NOW) == 0.4
    assert compute_confidence(1, thirty, NOW) == 0.2


def test_confidence_is_unknown_when_there_is_no_timestamp():
    assert compute_confidence(1, None, NOW) == 0.2


def test_a_second_source_raises_the_stored_confidence(tmp_path):
    db = tmp_path / "intel.db"
    import_indicators(db, [("ip", "203.0.113.9", "feed-a")], now=NOW)
    assert search_indicators(db, "203.0.113.9", now=NOW)[0].confidence == 0.6
    import_indicators(db, [("ip", "203.0.113.9", "feed-b")], now=NOW)
    assert search_indicators(db, "203.0.113.9", now=NOW)[0].confidence == 0.8
