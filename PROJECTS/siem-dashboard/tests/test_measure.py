"""The confusion matrix, on a corpus small enough to check by hand.

The measurement is the deliverable, so its arithmetic is tested against a corpus
whose right answer can be worked out on paper rather than against the real
capture, which would only prove the code agrees with itself.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from src.measure import RuleScore, load_corpus, measure_corpus, format_scores


class _FakeRule:
    def __init__(self, rule_id, techniques, title="t", level="High"):
        self.id = rule_id
        self.techniques = tuple(techniques)
        self.title = title
        self.level = level


class _FakeEngine:
    """A rule engine whose matching is decided by the test, not by YAML."""

    def __init__(self, rules, fires_on):
        self.rules = rules
        self._fires_on = fires_on      # rule_id -> set of window indices

    def match(self, payload):          # not used, but part of the shape
        return None


def _corpus(labels):
    """One event per window, so window and event counts coincide."""
    return {"windows": [{"label": label, "technique": label, "started": 0.0, "ended": 1.0,
                         "events": [{"channel": "System", "event_id": "1", "level": "Information",
                                     "message": "m", "fields": {}}]}
                        for label in labels]}


@pytest.fixture
def patched(monkeypatch):
    """Make `rule_matches` answer from the test's own table."""
    import src.measure as measure

    def install(rules, fires_on):
        def fake_rule_matches(fields, rule):
            # the argument is the *flattened* mapping event_fields() builds, and
            # EventData keys appear there bare as well as namespaced
            # event_fields stringifies every value, so the window tag arrives as text
            wanted = {str(item) for item in fires_on.get(rule.id, set())}
            return fields.get("__window__") in wanted
        monkeypatch.setattr(measure, "rule_matches", fake_rule_matches)
        return _FakeEngine(rules, fires_on)
    return install


def _measure(corpus, engine):
    """Tag each event with its window index so the fake matcher can decide."""
    tagged = {k: v for k, v in corpus.items() if k != "windows"}
    tagged["windows"] = []
    for index, window in enumerate(corpus["windows"]):
        events = [{**e, "fields": {"__window__": index}} for e in window["events"]]
        tagged["windows"].append({**window, "events": events})
    return measure_corpus(tagged, engine)


def test_a_rule_that_fires_on_its_own_technique_scores_a_true_positive(patched):
    rules = [_FakeRule("r1", ["T1082"])]
    engine = patched(rules, {"r1": {0}})
    result = _measure(_corpus(["T1082", "benign"]), engine)
    row = result["rules"][0]
    assert (row["tp"], row["fp"], row["fn"], row["tn"]) == (1, 0, 0, 1)
    assert row["precision"] == 1.0 and row["recall"] == 1.0 and row["f1"] == 1.0


def test_a_rule_that_fires_on_a_different_technique_is_a_false_positive(patched):
    """Firing on the wrong technique is not a detection.

    A rule that fires on anything would otherwise score perfectly, which is the
    flattery this definition exists to prevent.
    """
    rules = [_FakeRule("r1", ["T1082"])]
    engine = patched(rules, {"r1": {0}})
    result = _measure(_corpus(["T1057", "benign"]), engine)
    row = result["rules"][0]
    # a false positive but no false negative: the rule names T1082 and no window
    # in this corpus is labelled T1082, so there is nothing for it to have missed
    assert row["tp"] == 0 and row["fp"] == 1 and row["fn"] == 0 and row["tn"] == 1
    assert row["precision"] == 0.0
    assert row["recall"] is None


def test_a_rule_that_fires_on_benign_is_a_false_positive(patched):
    rules = [_FakeRule("r1", ["T1082"])]
    engine = patched(rules, {"r1": {1}})
    result = _measure(_corpus(["T1082", "benign"]), engine)
    row = result["rules"][0]
    assert row["tp"] == 0 and row["fp"] == 1 and row["fn"] == 1 and row["tn"] == 0
    assert row["precision"] == 0.0


def test_a_rule_that_never_fires_has_no_precision_rather_than_zero(patched):
    """No predictions is not the same as all predictions wrong."""
    rules = [_FakeRule("r1", ["T1082"])]
    engine = patched(rules, {})
    result = _measure(_corpus(["T1082", "benign"]), engine)
    row = result["rules"][0]
    assert row["tp"] == 0 and row["fp"] == 0 and row["fn"] == 1 and row["tn"] == 1
    assert row["precision"] is None
    assert row["recall"] == 0.0
    assert row["f1"] is None


def test_a_rule_firing_in_every_window_has_a_precision_of_zero(patched):
    """The measured result on this host, reproduced as arithmetic."""
    rules = [_FakeRule("noisy", ["T1082"])]
    engine = patched(rules, {"noisy": {0, 1, 2}})
    result = _measure(_corpus(["T1082", "benign", "benign"]), engine)
    row = result["rules"][0]
    assert row["fp"] == 2 and row["tp"] == 1
    assert row["precision"] == pytest.approx(1 / 3, abs=0.001)


def test_every_window_is_counted_exactly_once_per_rule(patched):
    rules = [_FakeRule("r1", ["T1082"]), _FakeRule("r2", [])]
    engine = patched(rules, {"r1": {0}})
    result = _measure(_corpus(["T1082", "benign", "benign"]), engine)
    for row in result["rules"]:
        assert row["tp"] + row["fp"] + row["fn"] + row["tn"] == 3


def test_the_summary_counts_the_corpus_it_was_given(patched):
    rules = [_FakeRule("r1", ["T1082"])]
    engine = patched(rules, {"r1": {0}})
    result = _measure(_corpus(["T1082", "T1057", "benign"]), engine)
    assert result["windows"] == 3
    assert result["benign_windows"] == 1
    assert result["events"] == 3
    assert result["techniques_in_corpus"] == ["T1057", "T1082"]


def test_scores_round_trip_through_a_dict():
    score = RuleScore("r", "title", "High", ("T1082",), 2, 1, 0, 3)
    as_dict = score.as_dict()
    assert as_dict["precision"] == 0.667
    assert as_dict["recall"] == 1.0
    assert as_dict["tp"] == 2


def test_the_report_names_the_blocked_techniques(patched):
    rules = [_FakeRule("r1", ["T1059.001"])]
    engine = patched(rules, {})
    corpus = _corpus(["benign"])
    corpus["blocked_techniques"] = [{"attack_id": "T1059.001", "name": "Encoded PowerShell",
                                     "reason": "endpoint protection refused the spawn"}]
    result = _measure(corpus, engine)
    text = format_scores(result)
    assert "T1059.001" in text
    assert "endpoint protection refused the spawn" in text


# --- the console's view of the measurement ---------------------------------

def test_a_snapshot_without_a_corpus_explains_itself(tmp_path):
    """No corpus is not an empty table. It is an experiment that has not been run."""
    from src.measure import measurement_snapshot
    result = measurement_snapshot(tmp_path / "absent.json", with_anomaly=False)
    assert result["available"] is False
    assert "not committed" in result["reason"]
    assert result["how_to_capture"]
    assert result["rules"] == []


def test_a_snapshot_over_a_corpus_reports_the_headline(tmp_path, patched):
    """The whole path: a corpus on disk becomes the numbers the console shows."""
    import json as _json
    from src.measure import measurement_snapshot
    rules = [_FakeRule("quiet", ["T1082"]), _FakeRule("noisy", [])]
    engine = patched(rules, {"noisy": {0, 1}})
    corpus = _corpus(["T1082", "benign"])
    tagged = {"windows": [
        {**w, "events": [{**e, "fields": {"__window__": i}} for e in w["events"]]}
        for i, w in enumerate(corpus["windows"])]}
    path = tmp_path / "corpus.json"
    path.write_text(_json.dumps(tagged), encoding="utf-8")

    result = measurement_snapshot(path, engine=engine, with_anomaly=False)
    assert result["available"] is True
    assert result["windows"] == 2
    assert result["summary"]["rules"] == 2
    assert result["summary"]["rules_that_detected_anything"] == 0
    assert result["summary"]["rules_with_false_positives"] == 1
    assert "2 rules" in result["summary"]["headline"]
    assert result["noisiest"][0]["rule_id"] == "noisy"
    assert result["noisiest"][0]["false_positives"] == 2


def test_the_default_corpus_path_is_overridable(monkeypatch, tmp_path):
    from src.measure import default_corpus_path
    monkeypatch.setenv("SIEM_LAB_CORPUS", str(tmp_path / "mine.json"))
    assert default_corpus_path() == tmp_path / "mine.json"


def test_the_default_corpus_path_falls_back_to_the_committed_fixture(monkeypatch):
    """A local capture wins; the committed fixture is what a fresh clone gets.

    Without this, CI and anyone reading the repository could see the measured
    numbers but not re-derive them, which for a project whose claim is "measured
    rather than assumed" is the wrong way round.
    """
    from src.measure import default_corpus_path
    monkeypatch.delenv("SIEM_LAB_CORPUS", raising=False)
    resolved = default_corpus_path()
    assert resolved.exists()
    assert resolved.name in ("corpus.json", "attack-lab-corpus.json")


def test_the_endpoint_serves_the_measurement(tmp_path, monkeypatch):
    """The console's endpoint, over the real Flask app.

    Without a corpus it must still answer, and answer with an explanation: the
    panel is loaded on every refresh, and on a machine that has not captured a
    corpus that is the normal case rather than an error.
    """
    from src.app import dashboard_app
    monkeypatch.setenv("SIEM_LAB_CORPUS", str(tmp_path / "absent.json"))
    client = dashboard_app(tmp_path / "live.db").test_client()
    response = client.get("/api/measurement")
    assert response.status_code == 200
    body = response.get_json()
    assert body["available"] is False
    assert body["how_to_capture"]
    assert "not committed" in body["reason"]


def test_the_endpoint_reports_over_a_real_corpus(tmp_path, monkeypatch):
    """And with one present, the numbers the panel renders."""
    import json as _json
    from src.app import dashboard_app
    corpus = {"windows": [
        {"label": "benign", "technique": "benign", "started": 0.0, "ended": 1.0,
         "events": [{"channel": "System", "event_id": "1", "level": "Information",
                     "message": "m", "fields": {}}]},
        {"label": "T1082", "technique": "T1082", "started": 0.0, "ended": 1.0,
         "events": [{"channel": "System", "event_id": "1", "level": "Information",
                     "message": "m", "fields": {}}]},
    ]}
    path = tmp_path / "corpus.json"
    path.write_text(_json.dumps(corpus), encoding="utf-8")
    monkeypatch.setenv("SIEM_LAB_CORPUS", str(path))

    client = dashboard_app(tmp_path / "live.db").test_client()
    body = client.get("/api/measurement").get_json()
    assert body["available"] is True
    assert body["windows"] == 2
    assert body["benign_windows"] == 1
    assert len(body["rules"]) == 28
    assert body["summary"]["headline"].endswith("windows.")
    # the detector is trained on the benign window, so it must have an answer
    assert "separation" in body.get("anomaly", {})
    assert 0.0 <= body["anomaly"]["benign_flagged"] <= 1.0


def test_the_dashboard_renders_the_measurement_panel():
    """The panel exists in the page, wired to the endpoint."""
    import pathlib
    page = pathlib.Path(__file__).resolve().parent.parent / "src" / "templates" / "dashboard.html"
    html = page.read_text(encoding="utf-8")
    assert 'id="measurement"' in html
    assert "/api/measurement" in html
    assert "refreshMeasurement" in html
    # a rule that fired on the wrong window must be visibly marked, not silently green
    assert "row.fp > 0" in html


def test_a_rule_the_corpus_never_exercised_is_marked_as_such(patched):
    """Twelve true negatives from a corpus that ran nothing it names are absences.

    Reporting them as a clean sheet is the most misleading thing a measurement
    like this can do: a rule that has never been tested looks exactly like a rule
    that was tested and passed.
    """
    rules = [_FakeRule("never-ran", ["T1059.001"])]
    engine = patched(rules, {})
    result = _measure(_corpus(["T1082", "benign"]), engine)
    row = result["rules"][0]
    assert row["tested"] is False
    assert row["evidence"] == "no evidence"
    assert row["precision"] is None and row["recall"] is None
    assert "no evidence" in format_scores(result)


def test_a_rule_that_fired_has_evidence_even_on_the_wrong_technique(patched):
    """Firing is evidence: it makes the precision a real number, if a bad one."""
    rules = [_FakeRule("noisy", ["T1059.001"])]
    engine = patched(rules, {"noisy": {0}})
    result = _measure(_corpus(["T1082", "benign"]), engine)
    row = result["rules"][0]
    assert row["tested"] is True
    assert row["precision"] == 0.0


def test_a_rule_naming_a_technique_that_ran_has_evidence(patched):
    rules = [_FakeRule("ran", ["T1082"])]
    engine = patched(rules, {})
    result = _measure(_corpus(["T1082", "benign"]), engine)
    row = result["rules"][0]
    assert row["tested"] is True
    assert row["recall"] == 0.0


# --- the committed fixture, so the numbers are reproducible ---------------

FIXTURE = Path(__file__).resolve().parent / "vectors" / "attack-lab-corpus.json"


def test_the_committed_fixture_is_present_and_scrubbed():
    """The capture is real telemetry from a real machine, so it is scrubbed.

    It is committed anyway, because a measurement a reader cannot re-derive is a
    claim rather than a measurement. The scrubbing is asserted here rather than
    trusted: a leak into a public repository is not something to find out about
    afterwards.
    """
    import re as _re
    assert FIXTURE.exists(), "the fixture must be committed for the numbers to be reproducible"
    blob = FIXTURE.read_text(encoding="utf-8")
    for pattern, what in ((r"LAPTOP-[A-Z0-9]+", "the machine name"),
                          (r"Khan", "the account name"),
                          (r"S-1-5-21-\d+-\d+-\d+-\d+", "a real SID"),
                          (r"tlsquic", "a scratch path")):
        assert not _re.search(pattern, blob, _re.I), what + " is still in the fixture"
    leftovers = {ip for ip in _re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", blob)
                 if not ip.startswith(("198.51.100.", "127.", "0.0.0.0"))}
    assert not leftovers, "real addresses remain: %s" % sorted(leftovers)[:5]


def test_the_fixture_reproduces_the_measured_result():
    """Every number in the README has to be re-derivable from the repository.

    This is the point of committing the fixture at all. If a rule's behaviour or
    a model's separation changes, this fails, which is what a documented result
    should do.
    """
    from src.anomaly import evaluate
    result = measure_corpus(load_corpus(FIXTURE))
    detected = {row["rule_id"] for row in result["rules"] if row["tp"] > 0}
    # the five discovery rules, plus the encoded-PowerShell rule -- which is in
    # here because the corpus finally contains a real encoded command, and it is
    # the only High-severity rule in the set that has ever been exercised
    assert detected == {
        "disc-system-information", "disc-process-listing", "disc-network-configuration",
        "disc-software-inventory", "disc-account-discovery",
        "sysmon-encoded-powershell-command",
    }, "the rules the README says detect something"
    assert result["windows"] == 17
    assert result["benign_windows"] == 6

    anomaly = evaluate(load_corpus(FIXTURE))
    visibility = anomaly["visibility"]
    assert visibility["separation"] > 0.5, "the forest must separate on the committed corpus"
    assert visibility["language_model"]["separation"] > 0.0
    # the window figure is weak by construction and is reported rather than hidden:
    # about ninety per cent of a window is ordinary activity, so the technique's
    # few events are averaged into nothing
    assert anomaly["window_operating_point"]["separation"] > 0.0
    assert anomaly["survived"] >= 1


def test_the_fixture_marks_the_untested_rules_as_untested():
    """The corpus runs five techniques, so most rules have no evidence in it."""
    result = measure_corpus(load_corpus(FIXTURE))
    untested = [row["rule_id"] for row in result["rules"] if not row["tested"]]
    # the encoded-PowerShell rule used to be one of these. It is not any more:
    # the corpus now contains a real encoded command, and the rule detects it.
    assert "sysmon-encoded-powershell-command" not in untested
    assert "win-audit-log-cleared" in untested
    assert len(untested) > 10


def test_the_snapshot_is_cached_until_the_corpus_changes(tmp_path):
    """The console asks for this on every refresh, and answering it is expensive.

    It scores every rule against every window and trains an isolation forest, so
    doing it per page refresh made the endpoint the slowest thing on the
    dashboard. Keyed on the file's modification time and size, so a new capture
    is still picked up by itself.
    """
    import json as _json
    from src.measure import measurement_snapshot
    path = tmp_path / "corpus.json"
    path.write_text(_json.dumps({"windows": [
        {"label": "benign", "events": []},
        {"label": "T1082", "events": []},
    ]}), encoding="utf-8")

    first = measurement_snapshot(path, with_anomaly=False)
    second = measurement_snapshot(path, with_anomaly=False)
    assert first is second, "the second call must be served from the cache"

    time.sleep(0.01)
    path.write_text(_json.dumps({"windows": [
        {"label": "benign", "events": []},
        {"label": "T1082", "events": []},
        {"label": "T1057", "events": []},
    ]}), encoding="utf-8")
    third = measurement_snapshot(path, with_anomaly=False)
    assert third is not first, "a changed corpus must be re-measured"
    assert third["windows"] == 3

    fresh = measurement_snapshot(path, with_anomaly=False, use_cache=False)
    assert fresh is not third


def test_a_sub_technique_keeps_its_number():
    """Splitting on the last dot collapsed every sub-technique to its number.

    attack.t1059.001 and attack.t1003.001 both became "001", so the LSASS rule
    counted the encoded-PowerShell window as one it names and reported a true
    positive for a technique it does not detect. The sub-technique is part of the
    identifier, so only the Sigma namespace is stripped.
    """
    from src.measure import _technique_key
    assert _technique_key("attack.t1059.001") == "T1059.001"
    assert _technique_key("attack.t1003.001") == "T1003.001"
    assert _technique_key("attack.t1059.001") != _technique_key("attack.t1003.001")
    assert _technique_key("T1082") == "T1082"
    assert _technique_key("attack.t1082") == "T1082"


# --- correlation -----------------------------------------------------------

def test_every_correlation_rule_fires_on_the_sequence_it_describes():
    """The four rules the plan's first bullet asks for, finally measured.

    A correlation rule does not judge one event: it fires when two detection
    rules match in order, on the same host or account, inside a window. Nothing
    had ever checked that, so the rules had no number attached.
    """
    from src.measure import measure_correlation
    result = measure_correlation()
    assert result["total"] >= 4
    for row in result["rules"]:
        assert row["fires_when_it_should"], "%s never fires on its own sequence" % row["rule_id"]
        assert row["verified_stimulus"], "%s uses a stimulus that proves nothing" % row["rule_id"]


def test_no_correlation_rule_fires_on_a_sequence_that_did_not_happen():
    """Wrong order, outside the window, split across hosts: none may fire.

    A rule that fires on any of those is reporting a sequence that did not occur,
    which is the failure mode correlation is most prone to and the reason the
    negatives exist.
    """
    from src.measure import measure_correlation
    result = measure_correlation()
    assert result["fired_when_they_should_not"] == 0
    for row in result["rules"]:
        assert row["fires_when_it_should_not"] == []
        assert row["precision"] == 1.0


def test_the_correlation_stimulus_actually_trips_its_detection_rule():
    """The scenarios are constructed, so each one is verified rather than assumed.

    The corpus contains no account creation, no lockout, no service install and no
    cleared log, so these sequences cannot come from it. What makes them usable is
    that every event is run through `rule_matches` against the rule it stands for
    before it is used -- a scenario cannot quietly stop representing what it says
    it represents.
    """
    from src.measure import measure_correlation
    result = measure_correlation()
    assert result["unverified_stimulus"] == 0


def test_correlation_report_reads_the_way_the_numbers_do():
    from src.measure import measure_correlation, format_correlation
    text = format_correlation(measure_correlation())
    assert "correlation rule" in text
    assert "spurious" in text
    assert "fire on the sequence they describe" in text


# --- the network rules, from the committed capture --------------------------

NETWORK_FIXTURE = Path(__file__).resolve().parent / "vectors" / "network-lab.pcap"


def test_the_network_rules_are_reproducible_from_the_committed_capture():
    """The three PCAP rules, re-derived from a capture anyone can check.

    Reporting that they measure at full precision with nothing behind it in the
    repository is a claim rather than a measurement, so the capture is committed
    and this re-derives the result from it.
    """
    from src import pcap_ingest
    from src.rules import RuleEngine, event_fields, rule_matches
    assert NETWORK_FIXTURE.exists(), "the capture must be committed"

    summary = pcap_ingest.read_capture(NETWORK_FIXTURE)
    payloads = pcap_ingest.flow_payloads(summary, capture_name="network-lab.pcap")
    assert payloads, "the capture must yield flows"

    engine = RuleEngine.from_directory()
    network = [rule for rule in engine.rules if rule.id.startswith("net-")]
    assert len(network) == 3

    def fired(rule_id):
        rule = next(r for r in network if r.id == rule_id)
        return any(rule_matches(event_fields(p), rule) for p in payloads)

    assert fired("net-cleartext-credential-service"), "the cleartext-service rule must fire"
    assert fired("net-telnet-usage"), "the telnet rule must fire"
    assert fired("net-high-volume-dns-txt"), "the large-TXT rule must fire"


def test_the_committed_capture_carries_no_identifying_traffic():
    """It is a capture of loopback traffic made for the lab, and it stays that way."""
    import re as _re
    raw = NETWORK_FIXTURE.read_bytes()
    text = b" ".join(_re.findall(rb"[ -~]{5,}", raw)).decode("ascii", "replace")
    for pattern in (r"Khan", r"LAPTOP-", r"tlsquic", r"hermes", r"@hotmail"):
        assert not _re.search(pattern, text, _re.I), pattern + " is in the capture"


def test_the_dns_reader_records_an_answer_size():
    """The field the large-TXT rule matches on, which nothing produced.

    `_dns_queries` returns early for a response, so the importer recorded only
    questions and never answers and the rule could not fire on any capture. The
    payloads now carry `response_bytes`.
    """
    from src import pcap_ingest
    summary = pcap_ingest.read_capture(NETWORK_FIXTURE)
    payloads = pcap_ingest.flow_payloads(summary, capture_name="network-lab.pcap")
    dns = [p for p in payloads if str((p.get("fields") or {}).get("protocol")) == "DNS"]
    assert dns, "the capture contains DNS"
    assert any("response_bytes" in (p.get("fields") or {}) for p in dns)
