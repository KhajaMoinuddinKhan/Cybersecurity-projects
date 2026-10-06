"""The confusion matrix, on a corpus small enough to check by hand.

The measurement is the deliverable, so its arithmetic is tested against a corpus
whose right answer can be worked out on paper rather than against the real
capture, which would only prove the code agrees with itself.
"""

from __future__ import annotations

import pytest

from src.measure import RuleScore, measure_corpus, format_scores


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
    monkeypatch.delenv("SIEM_LAB_CORPUS")
    assert default_corpus_path().name == "corpus.json"


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
