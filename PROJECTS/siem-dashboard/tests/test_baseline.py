"""Per-host behavioural baselining: bucketing, building, judging and clearing.

Every test drives the public functions against a real SQLite store created by
``app.get_connection``, so the module is exercised against the same schema the
running console uses. The baseline is built from small windows with small
``min_samples`` values so a test can state the arithmetic it expects.
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.app import get_connection
from src.baseline import (
    DEFAULT_MIN_SAMPLES,
    DEFAULT_WINDOW_HOURS,
    baseline_summary,
    bucket_counts,
    build_baseline,
    clear_baseline,
    detect_deviations,
    ensure_schema,
    list_baselines,
)


def make_conn(tmp_path):
    conn = get_connection(tmp_path / "live.db")
    ensure_schema(conn)
    return conn


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def hours_ago(hours):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")


def add_event(conn, host="LAB-A", channel="Security", rule_id="", timestamp=None, is_alert=0):
    """Insert one stored event and return nothing; commit once at the end."""

    conn.execute(
        "INSERT INTO live_events(timestamp,channel,provider,event_id,level,severity,username,host,"
        "source_ip,message,record_id,source,is_alert,rule_name,raw_log,external_id,rule_id) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            timestamp or _now(), channel, "provider", "1", "Information", "Low", "admin", host,
            "local", "message", "", "test", is_alert, "", "", "", rule_id,
        ),
    )


def add_burst(conn, host="LAB-A", channel="Security", rule_id="", count=1, timestamp=None):
    for _ in range(count):
        add_event(conn, host=host, channel=channel, rule_id=rule_id, timestamp=timestamp)
    conn.commit()


def rule_buckets(rows, host="LAB-A", key="r1"):
    return [row for row in rows if row["host"] == host and row["key_kind"] == "rule" and row["key_value"] == key]


def type_buckets(rows, host="LAB-A", key="Security"):
    return [row for row in rows if row["host"] == host and row["key_kind"] == "event_type" and row["key_value"] == key]


def build_varying(conn, host="LAB-A", channel="Security", rule_id="r1", counts=(1, 2, 1, 2, 1, 2)):
    """Insert one bucket per count, each an hour apart and all outside the last hour."""

    for offset, count in enumerate(counts, start=2):
        add_burst(conn, host=host, channel=channel, rule_id=rule_id, count=count, timestamp=hours_ago(offset))


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #

def test_ensure_schema_is_idempotent(tmp_path):
    conn = make_conn(tmp_path)
    ensure_schema(conn)  # a second call must not raise
    names = {
        str(row["name"])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert "baselines" in names


# --------------------------------------------------------------------------- #
# Bucketing
# --------------------------------------------------------------------------- #

def test_bucket_counts_groups_by_host_rule_and_hour(tmp_path):
    conn = make_conn(tmp_path)
    add_burst(conn, host="LAB-A", rule_id="r1", count=3, timestamp=hours_ago(2))
    add_burst(conn, host="LAB-A", rule_id="r1", count=2, timestamp=hours_ago(3))
    add_burst(conn, host="LAB-B", rule_id="r1", count=1, timestamp=hours_ago(2))

    rows = rule_buckets(bucket_counts(conn), host="LAB-A")
    assert [row["count"] for row in rows] == [2, 3]  # oldest hour first, one row per hour
    assert len({row["bucket"] for row in rows}) == 2
    assert len(rule_buckets(bucket_counts(conn), host="LAB-B")) == 1


def test_bucket_counts_truncates_to_the_hour(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, rule_id="r1", timestamp=hours_ago(2)[:13] + ":10:00")
    add_event(conn, rule_id="r1", timestamp=hours_ago(2)[:13] + ":50:00")
    conn.commit()

    rows = rule_buckets(bucket_counts(conn))
    assert len(rows) == 1
    assert rows[0]["count"] == 2
    assert rows[0]["bucket"].endswith(":00:00")


def test_bucket_counts_separates_rule_and_event_type_keys(tmp_path):
    conn = make_conn(tmp_path)
    add_burst(conn, channel="Security", rule_id="r1", count=2, timestamp=hours_ago(2))

    rows = bucket_counts(conn)
    assert len(rule_buckets(rows)) == 1
    assert len(type_buckets(rows, key="Security")) == 1
    # The event type key is the channel value, not the rule.
    assert {row["key_kind"] for row in rows} == {"rule", "event_type"}


def test_bucket_counts_excludes_empty_buckets(tmp_path):
    conn = make_conn(tmp_path)
    add_burst(conn, rule_id="r1", count=1, timestamp=hours_ago(2))
    add_burst(conn, rule_id="r1", count=1, timestamp=hours_ago(5))

    rows = rule_buckets(bucket_counts(conn))
    assert len(rows) == 2  # two active hours, not the 168 in the window
    assert all(row["count"] >= 1 for row in rows)


def test_bucket_counts_respects_hours_window(tmp_path):
    conn = make_conn(tmp_path)
    add_burst(conn, rule_id="r1", count=1, timestamp=hours_ago(2))
    add_burst(conn, rule_id="r1", count=1, timestamp=hours_ago(200))

    assert len(rule_buckets(bucket_counts(conn, hours=168))) == 1
    assert len(rule_buckets(bucket_counts(conn, hours=300))) == 2


def test_bucket_counts_counts_all_events_not_only_alerts(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, rule_id="r1", timestamp=hours_ago(2), is_alert=1)
    add_event(conn, rule_id="r1", timestamp=hours_ago(2), is_alert=0)
    conn.commit()

    assert rule_buckets(bucket_counts(conn))[0]["count"] == 2


def test_bucket_counts_ignores_empty_rule_id(tmp_path):
    conn = make_conn(tmp_path)
    add_burst(conn, channel="Security", rule_id="", count=1, timestamp=hours_ago(2))

    assert rule_buckets(bucket_counts(conn), key="") == []


@pytest.mark.parametrize("bad", [0, -1, "x", True, 1.5])
def test_bucket_counts_rejects_bad_hours(tmp_path, bad):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError):
        bucket_counts(conn, hours=bad)


# --------------------------------------------------------------------------- #
# Building
# --------------------------------------------------------------------------- #

def test_build_baseline_computes_mean_stddev_and_range(tmp_path):
    conn = make_conn(tmp_path)
    build_varying(conn, counts=(1, 2, 1, 2, 1, 2))

    result = build_baseline(conn, min_samples=6)
    assert result["built"] == 2  # the rule key and its event_type key
    assert result["skipped"] == 0

    stored = list_baselines(conn, kind="rule")[0]
    assert stored["sample_count"] == 6
    assert stored["mean"] == pytest.approx(1.5)
    assert stored["stddev"] == pytest.approx(0.5)  # population stddev
    assert stored["minimum"] == 1
    assert stored["maximum"] == 2
    assert stored["range"] == 1
    assert stored["first_observed"] < stored["last_observed"]


def test_build_baseline_skips_keys_with_too_few_samples(tmp_path):
    conn = make_conn(tmp_path)
    build_varying(conn, counts=(1, 1, 1))  # only three buckets

    result = build_baseline(conn, min_samples=6)
    assert result["built"] == 0
    assert result["skipped"] == 2  # the rule key and its event_type key
    assert list_baselines(conn) == []


def test_build_baseline_reports_window_and_threshold(tmp_path):
    conn = make_conn(tmp_path)
    build_varying(conn, counts=(1, 2, 1, 2))

    result = build_baseline(conn, hours=48, min_samples=4)
    assert result["window_hours"] == 48
    assert result["min_samples"] == 4


def test_build_baseline_updates_in_place_on_rebuild(tmp_path):
    conn = make_conn(tmp_path)
    build_varying(conn, counts=(1, 2, 1, 2, 1, 2))
    build_baseline(conn, min_samples=6)
    first = list_baselines(conn, kind="rule")[0]

    add_burst(conn, rule_id="r1", count=3, timestamp=hours_ago(8))  # two new hours
    add_burst(conn, rule_id="r1", count=3, timestamp=hours_ago(9))
    build_baseline(conn, min_samples=6)

    rows = list_baselines(conn, kind="rule")
    assert len(rows) == 1  # updated, not duplicated
    assert rows[0]["sample_count"] == 8
    assert rows[0]["maximum"] == 3
    assert rows[0]["mean"] != first["mean"]


@pytest.mark.parametrize("kwargs", [{"hours": 0}, {"min_samples": 0}, {"min_samples": "x"}, {"hours": True}])
def test_build_baseline_rejects_bad_input(tmp_path, kwargs):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError):
        build_baseline(conn, **kwargs)


# --------------------------------------------------------------------------- #
# Listing
# --------------------------------------------------------------------------- #

def test_list_baselines_filters_by_host_and_kind(tmp_path):
    conn = make_conn(tmp_path)
    build_varying(conn, host="LAB-A", rule_id="r1", counts=(1, 2, 1, 2, 1, 2))
    build_varying(conn, host="LAB-B", rule_id="r2", counts=(1, 2, 1, 2, 1, 2))
    build_baseline(conn, min_samples=6)

    assert len(list_baselines(conn)) == 4  # two hosts x (rule + event_type)
    assert {row["host"] for row in list_baselines(conn, host="LAB-A")} == {"LAB-A"}
    assert {row["key_kind"] for row in list_baselines(conn, kind="rule")} == {"rule"}
    assert all(row["key"] == f"{row['key_kind']}:{row['key_value']}" for row in list_baselines(conn))


def test_list_baselines_rejects_bad_kind(tmp_path):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError):
        list_baselines(conn, kind="nonsense")


def test_list_baselines_rejects_empty_host(tmp_path):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError):
        list_baselines(conn, host="  ")


# --------------------------------------------------------------------------- #
# Detecting deviations
# --------------------------------------------------------------------------- #

def test_detect_deviations_finds_a_genuine_deviation(tmp_path):
    conn = make_conn(tmp_path)
    build_varying(conn, rule_id="r1", counts=(1, 2, 1, 2, 1, 2))
    build_baseline(conn, min_samples=6)

    add_burst(conn, rule_id="r1", count=10)  # a burst in the current hour

    deviations = [d for d in detect_deviations(conn, sigma=3.0, min_samples=6) if d["key_kind"] == "rule"]
    assert len(deviations) == 1
    found = deviations[0]
    assert found["host"] == "LAB-A"
    assert found["key"] == "rule:r1"
    assert found["observed"] == 10
    assert found["expected"] == pytest.approx(1.5)
    assert found["stddev"] == pytest.approx(0.5)
    assert found["sigma_distance"] == pytest.approx(17.0)
    assert found["severity"] == "High"


def test_detect_deviations_ignores_a_normal_observation(tmp_path):
    conn = make_conn(tmp_path)
    build_varying(conn, rule_id="r1", counts=(1, 2, 1, 2, 1, 2))
    build_baseline(conn, min_samples=6)

    add_burst(conn, rule_id="r1", count=2)  # below mean + 3*stddev = 3.0

    assert detect_deviations(conn, sigma=3.0, min_samples=6) == []


def test_detect_deviations_honours_the_min_sample_guard(tmp_path):
    conn = make_conn(tmp_path)
    build_varying(conn, rule_id="r1", counts=(1, 2))  # two buckets, stored at min_samples=2
    build_baseline(conn, min_samples=2)
    assert list_baselines(conn, kind="rule")[0]["sample_count"] == 2

    add_burst(conn, rule_id="r1", count=10)

    # Too few samples to trust: not judged at the default guard.
    assert detect_deviations(conn, sigma=3.0, min_samples=6) == []
    # Judged only when the caller explicitly lowers the guard.
    low = detect_deviations(conn, sigma=3.0, min_samples=2)
    assert len([d for d in low if d["key_kind"] == "rule"]) == 1


def test_detect_deviations_grades_severity_by_sigma_distance(tmp_path):
    conn = make_conn(tmp_path)
    build_varying(conn, rule_id="r1", counts=(1, 2, 1, 2, 1, 2))
    build_baseline(conn, min_samples=6)

    add_burst(conn, rule_id="r1", count=5)  # distance (5 - 1.5) / 0.5 = 7.0 -> High

    found = [d for d in detect_deviations(conn, min_samples=6) if d["key_kind"] == "rule"][0]
    assert found["sigma_distance"] == pytest.approx(7.0)
    assert found["severity"] == "High"
    assert found["threshold"] == pytest.approx(3.0)


def test_detect_deviations_zero_variance_baseline(tmp_path):
    conn = make_conn(tmp_path)
    build_varying(conn, rule_id="r1", counts=(1, 1, 1))  # constant count, stddev 0
    build_baseline(conn, min_samples=3)

    add_burst(conn, rule_id="r1", count=1)  # equals the mean: not a deviation
    assert detect_deviations(conn, min_samples=3) == []

    add_burst(conn, rule_id="r1", count=4)  # above the mean: flagged without dividing by zero
    found = [d for d in detect_deviations(conn, min_samples=3) if d["key_kind"] == "rule"][0]
    assert found["sigma_distance"] is None
    assert found["severity"] == "High"


def test_detect_deviations_orders_furthest_first(tmp_path):
    conn = make_conn(tmp_path)
    build_varying(conn, rule_id="small", counts=(1, 2, 1, 2, 1, 2))  # stddev 0.5
    build_varying(conn, rule_id="flat", counts=(4, 4, 4, 4, 4, 4))  # stddev 0
    build_baseline(conn, min_samples=6)

    add_burst(conn, rule_id="small", count=6)  # distance 9.0
    add_burst(conn, rule_id="flat", count=6)  # distance None -> treated as furthest

    found = [d for d in detect_deviations(conn, min_samples=6) if d["key_kind"] == "rule"]
    assert found[0]["key"] == "rule:flat"
    assert found[0]["sigma_distance"] is None


@pytest.mark.parametrize(
    "kwargs",
    [{"window_minutes": 0}, {"sigma": 0}, {"sigma": -1}, {"sigma": "x"}, {"min_samples": 0}, {"window_minutes": True}],
)
def test_detect_deviations_rejects_bad_input(tmp_path, kwargs):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError):
        detect_deviations(conn, **kwargs)


# --------------------------------------------------------------------------- #
# Summary and clearing
# --------------------------------------------------------------------------- #

def test_baseline_summary_counts_keys_hosts_and_insufficient(tmp_path):
    conn = make_conn(tmp_path)
    build_varying(conn, host="LAB-A", rule_id="r1", counts=(1, 2, 1, 2, 1, 2))  # baselined
    build_varying(conn, host="LAB-B", rule_id="r2", counts=(1, 1))  # too few samples
    build_baseline(conn, min_samples=6)

    summary = baseline_summary(conn)
    assert summary["baselined"] == 2  # LAB-A rule + its event_type key
    assert summary["hosts"] == 1
    # LAB-B's rule key and its event_type key both have too few samples.
    assert summary["insufficient_history"] == 2
    assert summary["observed_keys"] == 4
    assert summary["min_samples"] == DEFAULT_MIN_SAMPLES
    assert summary["window_hours"] == DEFAULT_WINDOW_HOURS


def test_clear_baseline_by_host_and_all(tmp_path):
    conn = make_conn(tmp_path)
    build_varying(conn, host="LAB-A", rule_id="r1", counts=(1, 2, 1, 2, 1, 2))
    build_varying(conn, host="LAB-B", rule_id="r2", counts=(1, 2, 1, 2, 1, 2))
    build_baseline(conn, min_samples=6)

    removed = clear_baseline(conn, host="LAB-A")
    assert removed["host"] == "LAB-A"
    assert removed["deleted"] == 2
    assert {row["host"] for row in list_baselines(conn)} == {"LAB-B"}

    cleared = clear_baseline(conn)
    assert cleared["host"] is None
    assert cleared["deleted"] == 2
    assert list_baselines(conn) == []


def test_clear_baseline_rejects_empty_host(tmp_path):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError):
        clear_baseline(conn, host="")


# --------------------------------------------------------------------------- #
# Empty history
# --------------------------------------------------------------------------- #

def test_empty_history_end_to_end(tmp_path):
    conn = make_conn(tmp_path)

    assert bucket_counts(conn) == []
    assert build_baseline(conn) == {
        "built": 0,
        "skipped": 0,
        "window_hours": DEFAULT_WINDOW_HOURS,
        "min_samples": DEFAULT_MIN_SAMPLES,
    }
    assert list_baselines(conn) == []
    assert detect_deviations(conn) == []
    assert baseline_summary(conn) == {
        "baselined": 0,
        "hosts": 0,
        "insufficient_history": 0,
        "observed_keys": 0,
        "min_samples": DEFAULT_MIN_SAMPLES,
        "window_hours": DEFAULT_WINDOW_HOURS,
    }
    assert clear_baseline(conn) == {"deleted": 0, "host": None}
