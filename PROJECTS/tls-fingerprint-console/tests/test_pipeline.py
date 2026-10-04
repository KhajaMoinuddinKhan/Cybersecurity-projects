"""Pipeline and parser tests.

These cover two defects found by running the pipeline over a real capture
rather than by unit-testing the modules in isolation:

  * parse_http_request accepted ANY byte stream whose first line was non-empty,
    so a TLS record beginning 0x16 0x03 was parsed as a request and produced a
    JA4H built from a record header.
  * the pipeline fed a whole TLS stream to the HTTP parser for the same reason.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fixtures.make_pcap import (  # noqa: E402
    build_client_hello_record,
    build_http_get,
    make_classic_pcap,
    make_ipv6_pcap,
)
from src import tls as tlsmod  # noqa: E402
from src.corpus import load_corpus  # noqa: E402
from src.pipeline import events_from_pcap  # noqa: E402

CORPUS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "corpus"
)


# --------------------------------------------------------------- HTTP parsing

def test_http_parser_rejects_a_tls_record():
    with pytest.raises(ValueError):
        tlsmod.parse_http_request(build_client_hello_record())


@pytest.mark.parametrize("blob", [
    b"\x16\x03\x01\x00\x10garbage",
    b"this is not http at all\r\n\r\n",
    b"GET /only-two-parts\r\n\r\n",
    b"BOGUS / HTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET / HTTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET / HTTP/1.10\r\nHost: x\r\n\r\n",
    b"",
])
def test_http_parser_rejects_non_requests(blob):
    with pytest.raises(ValueError):
        tlsmod.parse_http_request(blob)


def test_http_parser_accepts_a_real_request():
    req = tlsmod.parse_http_request(
        b"GET /a HTTP/1.1\r\nHost: h\r\nUser-Agent: curl/8\r\n"
        b"Cookie: a=1; b=2\r\nReferer: https://x/\r\n\r\n"
    )
    assert req["method"] == "GET"
    assert req["version"] == "HTTP/1.1"
    assert req["cookie"] == "a=1; b=2"
    assert req["referer"] == "https://x/"
    # Host + User-Agent count; Cookie and Referer do not
    assert req["header_count"] == 2


# -------------------------------------------------------------------- pipeline

@pytest.fixture(scope="module")
def corpus():
    return load_corpus(CORPUS_DIR)


def test_pipeline_fingerprints_a_tls_flow(corpus):
    events = events_from_pcap(make_classic_pcap(), corpus)
    tls_events = [e for e in events if e["dst_port"] == 443]
    assert tls_events, "the TLS flow must produce an event"
    fp = tls_events[0]["fingerprints"]
    for kind in ("ja3", "ja3s", "ja4", "ja4s", "ja4x", "ja4t"):
        assert kind in fp, "missing %s" % kind
    assert tls_events[0]["sni"] == "example.com"
    assert fp["ja4"].startswith("t13d")


def test_pipeline_never_emits_a_fingerprint_built_from_tls_bytes(corpus):
    """The regression that started all this: a JA4H made of a record header."""
    events = events_from_pcap(make_classic_pcap(), corpus)
    for event in events:
        for kind, value in event["fingerprints"].items():
            assert "\x16" not in value, "%s contains a TLS record header: %r" % (kind, value)
            assert not value.startswith("\x16"), "%s starts with a TLS record" % kind


def test_pipeline_fingerprints_a_plaintext_http_flow(corpus):
    events = events_from_pcap(make_classic_pcap(), corpus)
    http_events = [e for e in events if e["dst_port"] == 80]
    assert http_events, "the plaintext HTTP flow must produce an event"
    fp = http_events[0]["fingerprints"]
    assert "ja4h" in fp
    assert fp["ja4h"].startswith("ge11"), "expected a GET / HTTP/1.1 fingerprint"
    assert http_events[0]["user_agent"], "the User-Agent must be read off the request"


def test_pipeline_handles_ipv6(corpus):
    events = events_from_pcap(make_ipv6_pcap(), corpus)
    assert events, "IPv6 flows must fingerprint too"
    assert any(e["fingerprints"].get("ja3") for e in events)


def test_pipeline_is_deterministic(corpus):
    a = events_from_pcap(make_classic_pcap(), corpus)
    b = events_from_pcap(make_classic_pcap(), corpus)
    assert [e["fingerprints"] for e in a] == [e["fingerprints"] for e in b]
