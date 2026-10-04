"""Exact-value tests for JA3 / JA3S (Salesforce) fingerprints.

The two published examples and their MD5 digests come straight from the
salesforce/ja3 README.  Input dicts are built by hand so the tests do not
depend on ``src.tls``.
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ja3 import ja3, ja3_raw, ja3s, ja3s_raw  # noqa: E402


def _hello(**overrides):
    hello = {
        "version": 769,
        "session_id": b"",
        "ciphers": [],
        "extensions": [],
        "sni": None,
        "alpn": [],
        "curves": [],
        "point_formats": [],
        "sig_algs": [],
        "supported_versions": [],
        "grease": [],
    }
    hello.update(overrides)
    return hello


def test_ja3_published_example_with_extensions():
    hello = _hello(
        version=769,
        ciphers=[47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4],
        extensions=[0, 10, 11],
        curves=[23, 24, 25],
        point_formats=[0],
    )
    assert ja3_raw(hello) == (
        "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
    )
    assert ja3(hello) == "ada70206e40642a3e4461f35503241d5"


def test_ja3_published_example_without_extensions():
    hello = _hello(
        version=769,
        ciphers=[4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99],
        extensions=[],
    )
    assert ja3_raw(hello) == "769,4-5-10-9-100-98-3-6-19-18-99,,,"
    assert ja3(hello) == "de350869b8c85de67a350c8d186f11e6"


def test_ja3_grease_is_ignored_everywhere():
    plain = _hello(
        version=769,
        ciphers=[47, 53, 5],
        extensions=[0, 10, 11],
        curves=[23, 24],
        point_formats=[0],
    )
    greased = _hello(
        version=769,
        ciphers=[0x0A0A, 47, 53, 5, 0x1A1A],
        extensions=[0x2A2A, 0, 10, 11],
        curves=[0x3A3A, 23, 24],
        point_formats=[0],
    )
    assert ja3_raw(greased) == ja3_raw(plain)
    assert ja3(greased) == ja3(plain)


def test_ja3s_raw_and_hash():
    hello = _hello(version=771, cipher=49200, extensions=[0, 11, 35, 65281])
    assert ja3s_raw(hello) == "771,49200,0-11-35-65281"
    assert ja3s(hello) == hashlib.md5(b"771,49200,0-11-35-65281").hexdigest()


def test_ja3s_ignores_grease():
    hello = _hello(
        version=771,
        cipher=49200,
        extensions=[0x0A0A, 0, 11, 0xFAFA, 35, 65281],
    )
    assert ja3s_raw(hello) == "771,49200,0-11-35-65281"


def test_ja3s_no_extensions_leaves_field_empty():
    hello = _hello(version=771, cipher=49200, extensions=[])
    assert ja3s_raw(hello) == "771,49200,"
    assert ja3s(hello) == hashlib.md5(b"771,49200,").hexdigest()
