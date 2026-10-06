"""The detector, and the properties that make its numbers mean something.

The forest is random, so the tests that matter are the ones that hold whatever
the seed: that it separates a clear outlier, that it is deterministic given a
seed, and that the evasion helpers change what they claim to change.
"""

from __future__ import annotations

import pytest

from src.anomaly import (FEATURES, FeatureExtractor, IsolationForest, _average_path_length,
                         evade_by_dilution, evade_by_mimicry, evaluate, format_report)


def _event(event_id="1", channel="System", level="Information", message="m",
           destination=None, image=r"C:\Windows\System32\svchost.exe", timestamp="2026-10-07T12:00:00"):
    fields = {"Image": image}
    if destination:
        fields["DestinationIp"] = destination
    return {"event_id": event_id, "channel": channel, "level": level, "message": message,
            "fields": fields, "timestamp": timestamp}


def test_the_feature_vector_has_the_declared_width():
    vector = FeatureExtractor().vector(_event())
    assert len(vector) == len(FEATURES)


def test_the_features_react_to_the_event():
    extractor = FeatureExtractor()
    plain = extractor.vector(_event(destination=None))
    networked = extractor.vector(_event(destination="203.0.113.9"))
    assert plain[4] == 0.0 and networked[4] == 1.0
    long_message = extractor.vector(_event(message="x" * 500))
    assert long_message[3] > plain[3]


def test_a_non_system_image_is_distinguished():
    extractor = FeatureExtractor()
    assert extractor.vector(_event(image=r"C:\Windows\System32\svchost.exe"))[5] == 1.0
    assert extractor.vector(_event(image=r"C:\Temp\evil.exe"))[5] == 0.0


def test_a_missing_event_id_does_not_raise():
    vector = FeatureExtractor().vector({"event_id": "not-a-number", "fields": {}})
    assert vector[0] == 0.0


def test_average_path_length_grows_with_size():
    lengths = [_average_path_length(n) for n in (2, 10, 100, 1000)]
    assert lengths == sorted(lengths)
    assert _average_path_length(1) == 0.0


def test_the_forest_separates_an_obvious_outlier():
    """A tight cluster and one point far away: the far point must score higher.

    This is the whole claim of an isolation forest, so it is asserted on data
    where the answer is not in doubt.
    """
    tight = [[0.0, 0.0, 0.0] for _ in range(60)]
    for index in range(60):
        tight[index] = [0.01 * (index % 3), 0.01 * (index % 2), 0.0]
    outlier = [50.0, 50.0, 50.0]
    forest = IsolationForest(trees=60, sample_size=32, seed=1).fit(tight)
    assert forest.score(outlier) > forest.score(tight[0])


def test_the_same_seed_gives_the_same_scores():
    data = [[float(i % 7), float(i % 5)] for i in range(40)]
    a = IsolationForest(trees=25, seed=99).fit(data).score_all(data)
    b = IsolationForest(trees=25, seed=99).fit(data).score_all(data)
    assert a == b


def test_a_different_seed_gives_a_different_forest():
    data = [[float(i % 7), float(i % 5)] for i in range(40)]
    a = IsolationForest(trees=25, seed=1).fit(data).score_all(data)
    b = IsolationForest(trees=25, seed=2).fit(data).score_all(data)
    assert a != b


def test_scoring_before_fitting_is_refused():
    with pytest.raises(ValueError):
        IsolationForest().score([0.0, 0.0])


def test_fitting_on_nothing_is_refused():
    with pytest.raises(ValueError):
        IsolationForest().fit([])


def test_dilution_adds_events_and_keeps_the_originals():
    attacks = [_event(event_id="7")]
    benign = [_event(event_id="2"), _event(event_id="3")]
    diluted = evade_by_dilution(attacks, benign, factor=5)
    assert len(diluted) == 1 + 5
    assert diluted[0] is attacks[0]


def test_mimicry_replaces_the_features_it_claims_to():
    extractor = FeatureExtractor()
    attacks = [_event(event_id="1", channel="System", level="High", message="a real command line",
                      image=r"C:\Temp\evil.exe")]
    benign = [_event(event_id="4688", channel="Security", level="Information",
                     message="x" * 300, image=r"C:\Windows\System32\svchost.exe")]
    mimicked = evade_by_mimicry(attacks, benign, extractor, seed=3)
    before = extractor.vector(attacks[0])
    after = extractor.vector(mimicked[0])
    donor = extractor.vector(benign[0])
    assert before != after
    # the features are now the benign ones, whatever those are: the assertion is
    # that they match the donor, not that they equal a remembered number
    assert after[1] == donor[1]
    assert after[5] == donor[5]
    assert after[3] == donor[3]


def test_mimicry_leaves_the_original_event_untouched():
    extractor = FeatureExtractor()
    attacks = [_event(event_id="1", image=r"C:\Temp\evil.exe")]
    benign = [_event(event_id="2")]
    evade_by_mimicry(attacks, benign, extractor)
    assert attacks[0]["event_id"] == "1"
    assert attacks[0]["fields"]["Image"] == r"C:\Temp\evil.exe"


def test_evaluate_needs_both_kinds_of_window():
    corpus = {"windows": [{"label": "benign", "events": [_event()]}]}
    with pytest.raises(ValueError):
        evaluate(corpus)


def test_evaluate_reports_a_separation_and_an_evasion_verdict():
    """A tiny corpus, but a real run end to end: train, score, evade, report."""
    benign = [_event(event_id=str(i % 3), message="ordinary") for i in range(40)]
    attack = [_event(event_id="4104", channel="Microsoft-Windows-PowerShell/Operational",
                     level="High", message="a distinctive command line", destination="203.0.113.9",
                     image=r"C:\Temp\evil.exe") for _ in range(12)]
    corpus = {"windows": [
        {"label": "benign", "events": benign},
        {"label": "T1082", "events": attack},
    ]}
    result = evaluate(corpus)
    assert result["trained_on_events"] == 40
    assert len(result["results"]) >= 3          # clean, mimicry, dilution
    assert result["attempts"] == len(result["results"]) - 1
    for row in result["results"]:
        assert 0.0 <= row["mean_flagged_benign"] <= 1.0
        assert 0.0 <= row["mean_flagged_attack"] <= 1.0
    text = format_report(result)
    assert "separation" in text
    assert "evasion attempts" in text
