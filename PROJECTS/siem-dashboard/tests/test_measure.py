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
        def fake_rule_matches(probe, rule):
            # the argument is the SIEM probe, so the window tag lives under "fields"
            window = (probe.get("fields") or {}).get("__window__")
            return window in fires_on.get(rule.id, set())
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
