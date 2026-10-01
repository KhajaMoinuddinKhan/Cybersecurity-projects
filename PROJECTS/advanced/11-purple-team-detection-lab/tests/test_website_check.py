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


def test_missing_security_headers_become_categorized_alerts():
    checks, findings, score = analyse_headers({}, True)
    assert checks["Content-Security-Policy"] is False
    assert any(
        item["category"] == "Security Header"
        and "Content Security Policy" in item["message"]
        for item in findings
    )
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


def test_empty_headers_are_missing():
    checks, findings, score = analyse_headers({"Content-Security-Policy": "  "}, True)
    assert checks["Content-Security-Policy"] is False
    assert score < 100


def test_connection_uses_validated_ip_without_second_hostname_lookup(monkeypatch):
    from src import website_check
    calls = []
    monkeypatch.setattr(website_check, "_public_ips", lambda host, port: ["93.184.215.14"])
    monkeypatch.setattr(website_check.socket, "create_connection", lambda *args: calls.append(args) or type("Socket", (), {"setsockopt": lambda *args: None})())
    connection = website_check.PublicHTTPConnection("example.com", timeout=2)
    connection.connect()
    assert calls == [(("93.184.215.14", 80), 2, None)]


def test_rebound_private_address_is_rejected_before_connect(monkeypatch):
    import pytest
    from src import website_check
    monkeypatch.setattr(website_check.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("127.0.0.1", 80))])
    def forbidden(*args, **kwargs):
        raise AssertionError("A private address must never be contacted")
    monkeypatch.setattr(website_check.socket, "create_connection", forbidden)
    with pytest.raises(ValueError, match="public internet"):
        website_check.PublicHTTPConnection("example.com").connect()
