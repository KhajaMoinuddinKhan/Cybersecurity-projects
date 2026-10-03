"""Score bands turn the total into a low, medium, or high verdict."""
from src.detector import score_url, verdict_for


def test_verdict_bands():
    assert verdict_for(0) == "low"
    assert verdict_for(2) == "low"
    assert verdict_for(3) == "medium"
    assert verdict_for(5) == "medium"
    assert verdict_for(6) == "high"
    assert verdict_for(100) == "high"


def test_low_risk_example():
    result = score_url("https://example.com/about")
    assert result.score == 0
    assert result.verdict == "low"
    assert result.label == "Lower risk by these rules"


def test_medium_risk_example():
    result = score_url("http://192.0.2.10/login/verify")
    assert result.verdict == "medium"
    assert result.label == "Potentially suspicious"


def test_high_risk_example():
    result = score_url("http://\u0430pple.com/login")
    assert result.score >= 6
    assert result.verdict == "high"
    assert result.label == "High risk by these rules"


def test_every_signal_reports_whether_it_fired():
    result = score_url("https://example.com/about")
    names = {outcome.name for outcome in result.outcomes}
    assert len(result.outcomes) == len(names)
    assert all(outcome.points == 0 for outcome in result.outcomes if not outcome.fired)
    assert all(outcome.points > 0 for outcome in result.outcomes if outcome.fired)
