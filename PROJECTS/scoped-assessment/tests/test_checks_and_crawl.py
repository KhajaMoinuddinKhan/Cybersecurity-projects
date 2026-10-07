"""The checks beyond the original three, the crawler, and the load limits.

These run against the lab, because the claim is that the tool finds things, and a
check that passes against a stub has proved nothing about a target.
"""

from __future__ import annotations

import json
import time

import pytest

from lab import LabServer
from src.assessment import CHECK_NAMES, CONFIRMABLE, assess_http
from src.crawl import STATE_CHANGING, crawl
from src.scope import load_scope
from src.throttle import RateExceeded, Throttle, TokenBucket


@pytest.fixture(scope="module")
def lab():
    with LabServer(port=0) as server:
        yield server


def engagement(tmp_path, ports, actions=("connect",)):
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps({
        "engagement": "test",
        "targets": [{"host": "127.0.0.1", "ports": list(ports)}],
        "allowed_actions": list(actions)}), encoding="utf-8")
    return load_scope(path, audit_path=tmp_path / "audit.jsonl")


@pytest.fixture(scope="module")
def findings(lab, tmp_path_factory):
    scope = engagement(tmp_path_factory.mktemp("scope"), [lab.port])
    return {f.id: f for f in assess_http(scope, "127.0.0.1", lab.port)}


# --- the checks ------------------------------------------------------------

def test_every_named_check_is_a_check_that_can_fire(findings):
    assert set(findings) == set(CHECK_NAMES)


@pytest.mark.parametrize("check", CHECK_NAMES)
def test_each_check_carries_evidence(findings, check):
    finding = findings[check]
    assert finding.evidence, "%s reported without evidence" % check
    assert finding.detail and finding.remediation and finding.business_impact


@pytest.mark.parametrize("check", CONFIRMABLE)
def test_each_confirmable_check_confirms_itself(findings, check):
    """Confirmation is a second observation, so a confirmable check that cannot
    confirm itself is either wrong about the target or wrong about the claim."""
    assert findings[check].confirmed is True, findings[check].confirmation


def test_an_absence_is_not_claimed_as_confirmed(findings):
    """The missing-header check is an absence and says so rather than borrowing the
    confidence of the checks that can look again."""
    finding = findings["missing-security-headers"]
    assert finding.confirmed is False
    assert "absence" in finding.confirmation.lower()


def test_the_listing_check_confirms_by_fetching_what_was_listed(findings):
    assert "requested directly" in findings["directory-listing"].confirmation


def test_the_vcs_check_recognises_a_real_git_file(findings):
    assert findings["vcs-exposed"].severity == "High"
    assert "version-control" in findings["vcs-exposed"].confirmation


def test_the_cookie_check_names_the_attributes_that_are_missing(findings):
    value = " ".join(str(item.get("value", "")) for item in findings["insecure-cookie"].evidence)
    assert "Set-Cookie" in value or "session=" in value
    assert "Secure" in findings["insecure-cookie"].detail


# --- the crawler -----------------------------------------------------------

def test_the_crawler_finds_the_pages_the_lab_links_to(tmp_path, lab):
    scope = engagement(tmp_path, [lab.port])
    result = crawl(scope, "127.0.0.1", lab.port)
    paths = {endpoint["path"] for endpoint in result["endpoints"]}
    assert "/" in paths
    assert "/search" in paths, "the search link is on every page"
    assert result["pages_read"] >= 4


def test_the_crawler_refuses_to_follow_a_state_changing_link(tmp_path, lab):
    """A crawler that follows every link eventually follows a delete."""
    scope = engagement(tmp_path, [lab.port])
    result = crawl(scope, "127.0.0.1", lab.port)
    skipped = {item["url"] for item in result["skipped"]}
    assert any("/logout" in url for url in skipped), skipped
    assert result["not_followed"] >= 1
    followed = {endpoint["path"] for endpoint in result["endpoints"]}
    assert "/logout" not in followed


def test_the_crawler_stays_on_the_host_it_started_from(tmp_path, lab):
    """A link to another host is somebody else's system."""
    scope = engagement(tmp_path, [lab.port])
    result = crawl(scope, "127.0.0.1", lab.port)
    for endpoint in result["endpoints"]:
        assert endpoint["url"].startswith("http://127.0.0.1:%d" % lab.port)


def test_the_crawler_records_the_fields_a_form_takes(tmp_path, lab):
    """A form is the application saying where it takes input, which is where the
    input checks belong."""
    scope = engagement(tmp_path, [lab.port])
    result = crawl(scope, "127.0.0.1", lab.port)
    forms = [endpoint for endpoint in result["endpoints"] if endpoint["form"]]
    assert forms, "the landing page carries a form"
    assert any("q" in endpoint["parameters"] for endpoint in forms)


def test_the_crawler_obeys_its_page_limit(tmp_path, lab):
    scope = engagement(tmp_path, [lab.port])
    result = crawl(scope, "127.0.0.1", lab.port, max_pages=2)
    assert result["pages_read"] <= 2


def test_the_crawler_never_reaches_a_port_outside_the_engagement(tmp_path, lab):
    scope = engagement(tmp_path, [lab.port + 1])
    result = crawl(scope, "127.0.0.1", lab.port)
    assert result["pages_read"] >= 1
    assert scope.audit.refusals, "every attempt has to appear in the log"


def test_a_crawl_with_no_pages_is_refused(tmp_path, lab):
    from src.crawl import CrawlError
    scope = engagement(tmp_path, [lab.port])
    with pytest.raises(CrawlError):
        crawl(scope, "127.0.0.1", lab.port, max_pages=0)


def test_the_state_changing_words_cover_the_obvious_ones():
    for word in ("logout", "delete", "shutdown"):
        assert word in STATE_CHANGING


# --- the load limits -------------------------------------------------------

def test_the_bucket_allows_a_burst_up_to_its_capacity():
    bucket = TokenBucket(rate_per_second=100, capacity=5)
    started = time.monotonic()
    for _ in range(5):
        bucket.acquire()
    assert time.monotonic() - started < 0.5, "five tokens should be there to take"


def test_the_bucket_holds_the_rate_over_time():
    """The long-run rate is what protects the target; a burst is what a bucket is
    for, but it cannot refill faster than the rate allows."""
    bucket = TokenBucket(rate_per_second=20, capacity=1)
    bucket.acquire()
    started = time.monotonic()
    for _ in range(5):
        bucket.acquire()
    elapsed = time.monotonic() - started
    assert elapsed >= 0.2, "five tokens at twenty a second cannot take less than 0.2s"


def test_a_request_larger_than_the_bucket_is_refused():
    bucket = TokenBucket(rate_per_second=10, capacity=2)
    with pytest.raises(RateExceeded):
        bucket.acquire(tokens=5)


def test_a_rate_of_zero_is_refused():
    with pytest.raises(ValueError):
        TokenBucket(rate_per_second=0)


def test_the_pool_runs_work_and_keeps_the_order():
    throttle = Throttle(rate_per_second=1000, workers=4)
    results = throttle.run([(lambda n=n: n * 2) for n in range(10)])
    assert results == [n * 2 for n in range(10)]
    assert throttle.completed == 10


def test_an_absurd_worker_count_is_refused():
    with pytest.raises(ValueError):
        Throttle(rate_per_second=10, workers=500)


def test_the_crawl_uses_the_throttle_and_reports_what_it_waited(tmp_path, lab):
    scope = engagement(tmp_path, [lab.port])
    throttle = Throttle(rate_per_second=1000, workers=4)
    crawl(scope, "127.0.0.1", lab.port, throttle=throttle)
    assert throttle.completed >= 1
    assert throttle.as_dict()["workers"] == 4
