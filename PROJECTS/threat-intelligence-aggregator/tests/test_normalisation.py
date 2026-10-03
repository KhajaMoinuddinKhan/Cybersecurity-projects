"""Type-specific normalisation and validation of indicator values."""
import pytest

from src.aggregator import canonicalise_value, normalise_row


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("EVIL.Example.COM.", "evil.example.com"),
        ("Bad-Domain.example", "bad-domain.example"),
        ("percent%example.test", "percent%example.test"),
    ],
)
def test_domains_are_lowercased_and_stripped(raw, expected):
    assert canonicalise_value("domain", raw) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("198.51.100.23", "198.51.100.23"),
        ("2001:0DB8::0001", "2001:db8::1"),
        ("198.51.100.0/24", "198.51.100.0/24"),
        # A host inside a network canonicalises to the network address.
        ("198.51.100.23/24", "198.51.100.0/24"),
    ],
)
def test_ips_are_canonicalised(raw, expected):
    assert canonicalise_value("ip", raw) == expected


@pytest.mark.parametrize(
    "length,algorithm_hex",
    [
        (32, "a" * 32),
        (40, "b" * 40),
        (64, "c" * 64),
        (128, "d" * 128),
    ],
)
def test_hashes_are_accepted_by_algorithm_length(length, algorithm_hex):
    assert canonicalise_value("hash", algorithm_hex.upper()) == algorithm_hex


def test_urls_lowercase_scheme_and_host():
    assert (
        canonicalise_value("url", "HTTP://Evil.Example/Malware/")
        == "http://evil.example/Malware"
    )


@pytest.mark.parametrize(
    "kind,raw",
    [
        ("ip", "999.1.1.1"),
        ("ip", "not-an-ip"),
        ("ip", "198.51.100.0/33"),
        ("domain", "has space.example"),
        ("domain", "a..b"),
        ("domain", "http://evil.example"),
        ("hash", "zzz"),
        ("hash", "abc123"),
        ("url", "not a url"),
        ("url", "evil.example/path"),
    ],
)
def test_malformed_values_are_rejected(kind, raw):
    with pytest.raises(ValueError):
        canonicalise_value(kind, raw)


def test_normalise_row_canonicalises_and_defaults_source():
    assert normalise_row({"type": " IP ", "value": " 2001:0DB8::1 "}) == (
        "ip",
        "2001:db8::1",
        "local",
    )


def test_normalise_row_uses_the_supplied_default_source():
    assert normalise_row({"type": "ip", "value": "8.8.8.8"}, "feed.csv") == (
        "ip",
        "8.8.8.8",
        "feed.csv",
    )
