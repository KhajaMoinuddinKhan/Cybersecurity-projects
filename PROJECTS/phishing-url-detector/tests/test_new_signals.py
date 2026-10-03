"""Each signal fires on its own example and stays quiet on a clean URL."""
from src.detector import evaluate_url, score_url

CLEAN = "https://example.com/about"


def fired_names(url):
    """Return the machine names of the signals that fired for a URL."""

    return {outcome.name for outcome in evaluate_url(url) if outcome.fired}


def reason_text(url):
    return " ".join(score_url(url).reasons)


def test_clean_url_fires_nothing():
    result = score_url(CLEAN)
    assert result.score == 0
    assert result.findings == ()
    assert result.reasons == ()


def test_plain_http_and_ip_host_are_kept():
    names = fired_names("http://192.0.2.10/")
    assert "plain_http" in names
    assert "ip_host" in names


def test_punycode_label_is_reported():
    names = fired_names("http://xn--pypal-4ve.com/login")
    assert "punycode_label" in names
    assert "xn--pypal-4ve" in reason_text("http://xn--pypal-4ve.com/login")


def test_homoglyph_characters_are_reported():
    url = "http://\u0430pple.com/"
    assert "homoglyph" in fired_names(url)
    assert "lookalike characters" in reason_text(url)


def test_ascii_host_has_no_homoglyph_finding():
    assert "homoglyph" not in fired_names(CLEAN)


def test_typosquat_reports_the_brand_it_resembles():
    url = "http://paypa1.com/login"
    assert "typosquat" in fired_names(url)
    assert "paypal.com" in reason_text(url)
    assert "edit distance 1" in reason_text(url)


def test_punycode_lookalike_is_named_as_such():
    url = "http://xn--pypal-4ve.com/"
    assert "lookalike of the brand behind paypal.com" in reason_text(url)


def test_real_brand_domain_is_not_a_typosquat():
    assert "typosquat" not in fired_names("https://paypal.com/login")
    assert "typosquat" not in fired_names("https://www.paypal.com/account")


def test_brand_in_subdomain_is_reported():
    url = "http://paypal.secure-login.evil.com/"
    assert "brand_in_host_or_path" in fired_names(url)
    assert "paypal in the subdomain" in reason_text(url)


def test_brand_in_path_is_reported():
    url = "http://evil.com/paypal/login"
    assert "brand_in_host_or_path" in fired_names(url)
    assert "paypal in the path" in reason_text(url)


def test_brand_in_its_own_domain_is_not_reported():
    assert "brand_in_host_or_path" not in fired_names("https://www.paypal.com/account")


def test_excessive_subdomain_depth_is_reported():
    url = "http://a.b.c.d.example.com/"
    assert "subdomain_depth" in fired_names(url)
    assert "excessive subdomain depth" in reason_text(url)


def test_modest_subdomain_depth_is_not_reported():
    assert "subdomain_depth" not in fired_names("https://www.example.com/about")


def test_suspicious_tld_is_reported():
    url = "http://login.example.tk/"
    assert "suspicious_tld" in fired_names(url)
    assert ".tk" in reason_text(url)


def test_common_tld_is_not_reported():
    assert "suspicious_tld" not in fired_names(CLEAN)


def test_very_long_url_is_reported():
    url = "http://example.com/" + "a" * 150
    assert "long_url" in fired_names(url)
    assert "unusually long" in reason_text(url)


def test_very_short_url_is_reported():
    url = "http://a.co"
    assert "short_url" in fired_names(url)
    assert "unusually short" in reason_text(url)


def test_ordinary_length_is_not_reported():
    names = fired_names(CLEAN)
    assert "long_url" not in names
    assert "short_url" not in names


def test_at_symbol_in_authority_is_reported():
    url = "http://user@example.com/login"
    assert "at_in_authority" in fired_names(url)


def test_nonstandard_port_is_reported():
    url = "http://example.com:8080/login"
    assert "nonstandard_port" in fired_names(url)
    assert "8080" in reason_text(url)


def test_standard_port_is_not_reported():
    assert "nonstandard_port" not in fired_names("https://example.com:443/about")


def test_deceptive_pdf_exe_extension_is_reported():
    url = "http://example.com/invoice.pdf.exe"
    assert "deceptive_extension" in fired_names(url)
    assert ".pdf.exe" in reason_text(url)


def test_deceptive_docx_html_extension_is_reported():
    url = "http://example.com/report.docx.html"
    assert "deceptive_extension" in fired_names(url)
    assert ".docx.html" in reason_text(url)


def test_single_document_extension_is_not_reported():
    assert "deceptive_extension" not in fired_names("https://example.com/file.pdf")


def test_heavy_percent_encoding_is_reported():
    url = "http://example.com/%2f%2f%2f%2f"
    assert "heavy_encoding" in fired_names(url)
    assert "heavily percent-encoded" in reason_text(url)


def test_light_percent_encoding_is_not_reported():
    assert "heavy_encoding" not in fired_names("https://example.com/a%20b")


def test_known_url_shortener_is_reported():
    url = "https://bit.ly/x"
    assert "url_shortener" in fired_names(url)
    assert "bit.ly" in reason_text(url)


def test_credential_harvesting_words_are_reported():
    url = "http://example.com/signin/wallet"
    names = fired_names(url)
    assert "suspicious_terms" in names
    text = reason_text(url)
    assert "signin" in text
    assert "wallet" in text


def test_helpers_compute_the_registrable_domain():
    from src.detector import registrable_domain

    assert registrable_domain("www.google.co.uk") == "google.co.uk"
    assert registrable_domain("a.b.example.com") == "example.com"
    assert registrable_domain("192.0.2.10") == ""
