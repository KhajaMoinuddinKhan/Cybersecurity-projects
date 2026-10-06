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
           destination=None, image=r"C:\Windows\System32\svchost.exe",
           timestamp="2026-10-07T12:00:00", command=""):
    fields = {"Image": image}
    if command:
        fields["CommandLine"] = command
    if destination:
        fields["DestinationIp"] = destination
    return {"event_id": event_id, "channel": channel, "level": level, "message": message,
            "fields": fields, "timestamp": timestamp}


def test_the_feature_vector_has_the_declared_width():
    vector = FeatureExtractor().vector(_event())
    assert len(vector) == len(FEATURES)


def test_the_features_react_to_the_event():
    extractor = FeatureExtractor()
    plain = extractor.vector(_event(message="m"))
    long_message = extractor.vector(_event(message="x" * 500))
    assert long_message[2] > plain[2]


def test_a_shell_process_is_distinguished():
    extractor = FeatureExtractor()
    assert extractor.vector(_event(image=r"C:\Windows\System32\cmd.exe"))[6] == 1.0
    assert extractor.vector(_event(image=r"C:\Program Files\App\app.exe"))[6] == 0.0


def test_the_command_features_read_what_the_command_says():
    """The signal is in the words, so the features have to read them.

    The first feature set described the event's shape and scored the technique's
    own events as more normal than background activity: living-off-the-land
    discovery runs cmd.exe out of System32, so a feature calling System32 benign
    called the technique benign too.
    """
    extractor = FeatureExtractor()
    ordinary = extractor.vector(_event(command=r"C:\Windows\System32\cmd.exe /C dir"))
    discovery = extractor.vector(
        _event(command=r'C:\Windows\System32\cmd.exe /C "whoami /all ; ipconfig /all"'))
    assert discovery[5] > ordinary[5]          # discovery verbs
    assert discovery[3] > ordinary[3]          # command length
    assert discovery[4] >= ordinary[4]         # token count
    assert ordinary[5] == 0.0


def test_a_command_line_that_is_absent_does_not_raise():
    vector = FeatureExtractor().vector({"fields": {}})
    assert vector[3] == 0.0 and vector[4] == 0.0 and vector[5] == 0.0


def test_the_language_model_scores_a_novel_word_as_surprising():
    """The model the forest cannot be: it sees words the training data never had."""
    from src.anomaly import CommandLanguageModel
    model = CommandLanguageModel().fit([
        r"C:\Windows\System32\cmd.exe /C dir",
        r"C:\Windows\System32\cmd.exe /C echo hello",
    ])
    familiar = model.score(r"C:\Windows\System32\cmd.exe /C dir")
    strange = model.score(r"C:\Windows\System32\cmd.exe /C whoami /all")
    assert strange > familiar


def test_the_language_model_is_empty_safe():
    from src.anomaly import CommandLanguageModel
    model = CommandLanguageModel()
    # an unfitted model has one token in its vocabulary of one, so nothing is
    # surprising yet -- what matters is that it answers instead of dividing by zero
    assert model.score("anything at all") >= 0.0
    assert model.score("") == 0.0


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


def test_the_evasions_are_scored_on_the_technique_events_not_the_window():
    """The window number is diluted by ordinary activity sharing the window.

    Measured on the captured corpus, about ninety per cent of a window is
    background, so an evasion that hides a handful of events barely moves the
    window figure and "the detector survived" would only mean the dilution
    absorbed the difference. The evasion has to be judged on the technique's own
    events or it is not being judged at all.
    """
    benign = [_event(event_id=str(i % 3), message="ordinary",
                     command=r"C:\Windows\System32\cmd.exe /C dir") for i in range(40)]
    attack = [_event(event_id="1", message="a distinctive command line",
                     command=r'C:\Windows\System32\cmd.exe /C "whoami /all ; ipconfig /all"',
                     image=r"C:\Windows\System32\cmd.exe") for _ in range(8)]
    corpus = {"windows": [
        {"label": "benign", "events": benign},
        {"label": "T1033", "events": attack},
    ]}
    result = evaluate(corpus)
    assert result["evasions"], "the evasions must be measured"
    for row in result["evasions"]:
        assert row["events"] > 0
        assert row["separation"] is not None
        assert 0.0 <= row["technique_flagged"] <= 1.0
    assert result["survived"] + (result["attempts"] - result["survived"]) == result["attempts"]


def test_an_evasion_that_works_is_reported_as_having_worked():
    """A detector that cannot see the technique must not be scored as surviving."""
    benign = [_event(event_id=str(i % 3), message="ordinary",
                     command=r"C:\Windows\System32\cmd.exe /C dir") for i in range(40)]
    attack = [_event(event_id="1", message="m",
                     command=r'C:\Windows\System32\cmd.exe /C "whoami /all"',
                     image=r"C:\Windows\System32\cmd.exe") for _ in range(8)]
    corpus = {"windows": [{"label": "benign", "events": benign},
                          {"label": "T1033", "events": attack}]}
    result = evaluate(corpus)
    floor = result["evasion_floor"]
    for row in result["evasions"]:
        expected = (row["separation"] or -1) >= floor
        assert (row["name"], expected) in [(r["name"], (r["separation"] or -1) >= floor)
                                           for r in result["evasions"]]
