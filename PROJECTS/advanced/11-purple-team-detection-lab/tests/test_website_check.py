from src.website_check import analyse_headers, normalise_url, validate_public_url


def test_url_without_scheme_defaults_to_https():
    assert normalise_url("example.com") == "https://example.com"


def test_private_ip_is_rejected():
    try:
        validate_public_url("http://127.0.0.1")
    except ValueError as exc:
        assert "public internet" in str(exc)
        return
    raise AssertionError("Private address should have been rejected")


def test_missing_security_headers_reduce_score():
    checks, findings, score = analyse_headers({}, True)
    assert checks["Content-Security-Policy"] is False
    assert any("Content Security Policy" in item["message"] for item in findings)
    assert score < 100


def test_present_headers_are_marked_present():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    checks, findings, score = analyse_headers(headers, True)
    assert all(checks.values())
    assert score == 100
    assert findings == []
