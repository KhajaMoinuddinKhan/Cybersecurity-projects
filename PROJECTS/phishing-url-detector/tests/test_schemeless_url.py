"""A scheme is only a scheme at the start of the URL."""
from src.detector import normalise_url, score_url


def test_scheme_like_text_in_the_path_is_still_treated_as_http():
    value = "example.com/redirect?url=http://evil.com"
    assert normalise_url(value) == f"http://{value}"
    result = score_url(value)
    assert "hostname is missing" not in result.reasons
    assert result.score == 1


def test_protocol_relative_url_keeps_its_host():
    assert normalise_url("//example.com/about") == "http://example.com/about"
    result = score_url("//example.com/about")
    assert "hostname is missing" not in result.reasons
