from src.detector import score_url

def test_suspicious_training_url_is_flagged():
    result=score_url("http://192.0.2.10/login/verify")
    reasons=" ".join(result.reasons)
    assert result.score>=3
    assert "IP address" in reasons
    assert "many subdomain levels" not in reasons

def test_simple_https_url_is_low_risk_by_rules():
    result=score_url("https://example.com/about")
    assert result.score==0
    assert result.reasons==()
