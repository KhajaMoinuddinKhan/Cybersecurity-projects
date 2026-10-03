"""Search across every type and the summary counts."""
from datetime import datetime, timezone

from src.aggregator import collect_stats, import_indicators, search_indicators

NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)


def _seed(db):
    import_indicators(
        db,
        [
            ("ip", "198.51.100.23", "feed-a"),
            ("domain", "bad.example", "feed-b"),
            ("hash", "44d88612fea8a8f36de82e1278abb02f", "feed-c"),
            ("url", "http://evil.example/malware", "feed-d"),
        ],
        now=NOW,
    )


def test_search_finds_every_indicator_type(tmp_path):
    db = tmp_path / "intel.db"
    _seed(db)

    assert search_indicators(db, "198.51.100.23", now=NOW)[0].type == "ip"
    assert search_indicators(db, "bad.example", now=NOW)[0].type == "domain"
    assert search_indicators(db, "44d88612", now=NOW)[0].type == "hash"
    assert search_indicators(db, "evil.example", now=NOW)[0].type == "url"


def test_a_hit_reports_its_sources_and_age(tmp_path):
    db = tmp_path / "intel.db"
    _seed(db)

    hit = search_indicators(db, "198.51.100.23", now=NOW)[0]
    assert hit.sources == ["feed-a"]
    assert hit.age_days == 0
    assert hit.age_band == "0-7d"


def test_search_still_treats_wildcards_as_plain_text(tmp_path):
    db = tmp_path / "intel.db"
    import_indicators(
        db,
        [("domain", "percent%example.test", "feed-a"), ("domain", "plain.example", "feed-a")],
        now=NOW,
    )
    hits = search_indicators(db, "%", now=NOW)
    assert [hit.value for hit in hits] == ["percent%example.test"]


def test_stats_count_by_type_source_and_age(tmp_path):
    db = tmp_path / "intel.db"
    import_indicators(
        db,
        [
            ("ip", "198.51.100.23", "feed-a"),
            ("ip", "203.0.113.9", "feed-b"),
            ("domain", "bad.example", "feed-a"),
        ],
        now=NOW,
    )

    stats = collect_stats(db, now=NOW)
    assert stats.total == 3
    assert dict(stats.by_type) == {"ip": 2, "domain": 1}
    assert dict(stats.by_source) == {"feed-a": 2, "feed-b": 1}
    assert dict(stats.by_age)["0-7d"] == 3


def test_stats_place_an_old_indicator_in_the_stale_band(tmp_path):
    db = tmp_path / "intel.db"
    import_indicators(
        db,
        [("ip", "198.51.100.23", "feed-a")],
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    stats = collect_stats(db, now=NOW)
    assert dict(stats.by_age)["90d+"] == 1
