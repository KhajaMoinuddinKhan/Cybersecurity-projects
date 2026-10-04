"""Exact-value tests for the JA4 family (JA4, JA4S, JA4X, JA4T, JA4H).

Published examples are asserted verbatim:

* JA4 worked example from FoxIO technical_details/JA4.md.
* JA4 extension-hash example with and without signature algorithms.
* JA4S examples (server fingerprints; inputs rebuilt from the published
  raw extension lists / published hashes).
* JA4X self-signed certificate example.
* JA4T TCP SYN example.
* JA4H examples (cookie + no-cookie + referer/language).

All ClientHello / ServerHello / request dicts are built by hand so the tests
do not depend on ``src.tls``.
"""

import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ja4 import ja4, ja4_r, ja4h, ja4s, ja4t, ja4x  # noqa: E402

# --------------------------------------------------------------------------
# Shared worked-example ClientHello (FoxIO technical_details/JA4.md).
# --------------------------------------------------------------------------
WORKED_CIPHERS = [
    0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9,
    0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
]
WORKED_EXTENSIONS = [
    0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D, 0x000D,
    0x0005, 0x0023, 0x0012, 0x002B, 0xFF01, 0x000B, 0x000A, 0x0015,
]
WORKED_SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def worked_hello(**overrides):
    hello = {
        "version": 0x0303,
        "session_id": b"",
        "ciphers": list(WORKED_CIPHERS),
        "extensions": list(WORKED_EXTENSIONS),
        "sni": "example.com",
        "alpn": [b"h2"],
        "curves": [0x001D, 0x0017, 0x0018],
        "point_formats": [0],
        "sig_algs": list(WORKED_SIG_ALGS),
        "supported_versions": [0x0304],
        "grease": [],
    }
    hello.update(overrides)
    return hello


# ==========================================================================
# JA4
# ==========================================================================

def test_ja4_worked_example():
    assert ja4(worked_hello()) == "t13d1516h2_8daaf6152771_e5627efa2ab1"


def test_ja4_r_worked_example():
    assert ja4_r(worked_hello()) == (
        "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,"
        "c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,"
        "002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
    )


def test_ja4_extension_hash_without_signature_algorithms():
    # FoxIO JA4.md: sorted extensions with no sig-algs hash to 6d807ffa2a79.
    assert ja4(worked_hello(sig_algs=[])) == (
        "t13d1516h2_8daaf6152771_6d807ffa2a79"
    )


def test_ja4_ignores_grease_in_every_field():
    greased = worked_hello(
        ciphers=[0x0A0A] + list(WORKED_CIPHERS) + [0xFAFA],
        extensions=[0x1A1A] + list(WORKED_EXTENSIONS) + [0x2A2A],
        supported_versions=[0x3A3A, 0x0304],
    )
    assert ja4(greased) == "t13d1516h2_8daaf6152771_e5627efa2ab1"


def test_ja4_counts_scsv_and_experimental_ciphers():
    hello = worked_hello(
        ciphers=[0x00FF, 0x5600, 0xFE00],
        extensions=[],
        sig_algs=[],
        sni=None,
        alpn=[],
        supported_versions=[],
    )
    assert ja4(hello) == "t12i030000_5ba93aac7bbb_000000000000"


def test_ja4_empty_cipher_list_hashes_to_zeros():
    hello = worked_hello(ciphers=[], extensions=[], sig_algs=[], sni=None, alpn=[])
    assert ja4(hello).split("_")[1] == "000000000000"


def test_ja4_grease_only_cipher_list_hashes_to_zeros():
    hello = worked_hello(ciphers=[0x0A0A, 0x1A1A, 0xFAFA])
    fp = ja4(hello)
    assert fp.split("_")[1] == "000000000000"
    assert fp[4:6] == "00"  # cipher count ignores GREASE


def test_ja4_empty_extension_list_hashes_to_zeros():
    hello = worked_hello(extensions=[], sig_algs=[], sni=None, alpn=[])
    assert ja4(hello).split("_")[2] == "000000000000"


def test_ja4_no_sni_uses_i():
    exts = [e for e in WORKED_EXTENSIONS if e != 0x0000]
    fp = ja4(worked_hello(extensions=exts, sni=None))
    assert fp[3] == "i"


def test_ja4_version_prefers_highest_supported_version():
    assert ja4(worked_hello(supported_versions=[0x0303, 0x0304]))[1:3] == "13"


def test_ja4_version_ignores_grease_in_supported_versions():
    assert ja4(worked_hello(supported_versions=[0x0A0A, 0x0303]))[1:3] == "12"


def test_ja4_version_falls_back_to_protocol_version():
    assert ja4(worked_hello(supported_versions=[]))[1:3] == "12"


@pytest.mark.parametrize(
    "alpn, expected",
    [
        ([b"h2"], "h2"),
        ([b"http/1.1"], "h1"),
        ([b"x"], "xx"),
        ([], "00"),
        (None, "00"),
        ([b""], "00"),
        ([b"\xab"], "ab"),
        ([b"\x20"], "20"),
        ([b"\xab\xcd"], "ad"),
        ([b"\x20\x61"], "21"),
        ([b"\x30\xab"], "3b"),
        ([b"\x61\x20"], "60"),
        ([b"\x30\x31\xab\xcd"], "3d"),
        ([b"\x30\xab\xcd\x31"], "01"),
    ],
)
def test_ja4_alpn_encoding(alpn, expected):
    assert ja4(worked_hello(alpn=alpn))[8:10] == expected


def test_ja4_protocol_character_is_configurable():
    assert ja4(worked_hello(), proto="q").startswith("q13d")
    assert ja4(worked_hello(), proto="d").startswith("d13d")


# ==========================================================================
# JA4S
# ==========================================================================

def test_ja4s_published_example():
    hello = {
        "version": 0x0303,
        "cipher": 0xC030,
        "extensions": [0x0005, 0x0017, 0xFF01, 0x0000],
        "alpn": None,
    }
    assert ja4s(hello) == "t120400_c030_4e8089b08790"


def test_ja4s_foxio_sigalg_grease_example():
    hello = {"version": 0x0304, "cipher": 0x1302,
             "extensions": [0x0033, 0x002B], "alpn": None}
    assert ja4s(hello) == "t130200_1302_234ea6891581"


def test_ja4s_with_alpn():
    hello = {"version": 0x0303, "cipher": 0xCCA9,
             "extensions": [0x0000, 0xFF01, 0x000B, 0x0010], "alpn": b"h2"}
    assert ja4s(hello) == "t1204h2_cca9_1428ce7b4018"


def test_ja4s_ignores_grease():
    hello = {
        "version": 0x0303,
        "cipher": 0xC030,
        "extensions": [0x0A0A, 0x0005, 0x0017, 0xFF01, 0x0000, 0x1A1A],
        "alpn": None,
    }
    assert ja4s(hello) == "t120400_c030_4e8089b08790"


def test_ja4s_empty_extensions_hashes_to_zeros():
    hello = {"version": 0x0303, "cipher": 0xC02F, "extensions": [], "alpn": None}
    assert ja4s(hello) == "t120000_c02f_000000000000"


# ==========================================================================
# JA4X -- build minimal DER certificates with the stdlib only
# ==========================================================================

def _der_len(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag, content):
    return bytes([tag]) + _der_len(len(content)) + content


def _seq(*items):
    return _tlv(0x30, b"".join(items))


def _set(*items):
    return _tlv(0x31, b"".join(items))


def _oid(dotted):
    arcs = [int(part) for part in dotted.split(".")]
    body = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            chunk.insert(0, (arc & 0x7F) | 0x80)
            arc >>= 7
        body.extend(chunk)
    return _tlv(0x06, bytes(body))


def _integer(value):
    raw = value.to_bytes((value.bit_length() // 8) + 1, "big")
    return _tlv(0x02, raw)


def _rdn(oid):
    return _set(_seq(_oid(oid), _tlv(0x0C, b"x")))  # UTF8String value


def _name(oids):
    return _seq(*[_rdn(oid) for oid in oids])


def _extension(oid):
    return _seq(_oid(oid), _tlv(0x04, b""))


def _make_cert(issuer, subject, extensions):
    tbs = _seq(
        _tlv(0xA0, _integer(2)),                                   # version v3
        _integer(0x1234),                                          # serialNumber
        _seq(_oid("1.2.840.113549.1.1.11"), _tlv(0x05, b"")),      # signature
        _name(issuer),
        _seq(_tlv(0x17, b"200101000000Z"), _tlv(0x17, b"210101000000Z")),
        _name(subject),
        _seq(_oid("1.2.840.113549.1.1.1"), _tlv(0x05, b"")),       # SPKI
        _tlv(0xA3, _seq(*[_extension(oid) for oid in extensions])),
    )
    return _seq(
        tbs,
        _seq(_oid("1.2.840.113549.1.1.11"), _tlv(0x05, b"")),
        _tlv(0x03, b""),
    )


def test_ja4x_published_example():
    cert = _make_cert(
        issuer=["2.5.4.3", "2.5.4.6", "2.5.4.8", "2.5.4.10"],
        subject=["2.5.4.3", "2.5.4.6", "2.5.4.8", "2.5.4.10"],
        extensions=["2.5.29.15", "2.5.29.37", "2.5.29.17"],
    )
    assert ja4x(cert) == "96a6439c8f5c_96a6439c8f5c_aae71e8db6d7"


def test_ja4x_absent_fields_render_as_ten_zeros():
    cert = _make_cert(issuer=[], subject=["2.5.4.3"], extensions=[])
    issuer_hash, subject_hash, ext_hash = ja4x(cert).split("_")
    assert issuer_hash == "0000000000"
    assert len(issuer_hash) == 10
    assert ext_hash == "0000000000"
    assert len(ext_hash) == 10
    assert subject_hash == hashlib.sha256(b"550403").hexdigest()[:12]


def test_ja4x_rdn_order_matters():
    forward = _make_cert(["2.5.4.3", "2.5.4.10"], ["2.5.4.3", "2.5.4.10"], [])
    reverse = _make_cert(["2.5.4.10", "2.5.4.3"], ["2.5.4.10", "2.5.4.3"], [])
    assert ja4x(forward).split("_")[0] != ja4x(reverse).split("_")[0]


def test_ja4x_self_signed_issuer_equals_subject():
    cert = _make_cert(["2.5.4.3"], ["2.5.4.3"], ["2.5.29.15"])
    issuer_hash, subject_hash, _ = ja4x(cert).split("_")
    assert issuer_hash == subject_hash


# ==========================================================================
# JA4T
# ==========================================================================

def test_ja4t_published_example():
    syn = {"window": 65535, "options": [2, 1, 3, 1, 1, 4],
           "mss": 1460, "window_scale": 8}
    assert ja4t(syn) == "65535_2-1-3-1-1-4_1460_8"


def test_ja4t_missing_mss_and_scale_render_as_zero():
    syn = {"window": 29200, "options": [2, 4, 8, 1, 3],
           "mss": None, "window_scale": None}
    assert ja4t(syn) == "29200_2-4-8-1-3_0_0"


# ==========================================================================
# JA4H
# ==========================================================================

def test_ja4h_published_cookie_example():
    cookie = "yummy_cookie=choco; tasty_cookie=strawberry"
    req = {
        "method": "GET",
        "version": "HTTP/1.1",
        "headers": [
            ("Host", "example.com"),
            ("User-Agent", "Mozilla/5.0"),
            ("Accept", "*/*"),
            ("Accept-Language", "da"),
            ("Cookie", cookie),
            ("Referer", "https://example.com/"),
        ],
        "cookie": cookie,
        "referer": "https://example.com/",
        "language": "da",
        "header_count": 4,
    }
    assert ja4h(req) == "ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442"


def test_ja4h_no_cookie_referer_or_language():
    req = {
        "method": "GET",
        "version": "HTTP/1.0",
        "headers": [("User-Agent", "curl/8.0")],
        "cookie": None,
        "referer": None,
        "language": None,
        "header_count": 1,
    }
    assert ja4h(req) == "ge10nn010000_b8bcd45ac095_000000000000_000000000000"


def test_ja4h_referer_and_language():
    req = {
        "method": "GET",
        "version": "HTTP/1.1",
        "headers": [
            ("Host", "example.org"),
            ("Connection", "keep-alive"),
            ("User-Agent", "Mozilla/5.0"),
            ("Accept", "*/*"),
            ("Accept-Encoding", "gzip"),
            ("Accept-Language", "ru-RU"),
            ("Referer", "https://example.org/"),
        ],
        "cookie": None,
        "referer": "https://example.org/",
        "language": "ru-RU",
        "header_count": 6,
    }
    assert ja4h(req) == "ge11nr06ruru_cc6ec9a91856_000000000000_000000000000"


def test_ja4h_http2_and_pseudo_headers_excluded():
    req = {
        "method": "GET",
        "version": "2.0",
        "headers": [(":method", "GET"), (":path", "/"), ("user-agent", "x")],
        "cookie": None,
        "referer": None,
        "language": "en-US",
        "header_count": 1,
    }
    fp = ja4h(req)
    assert fp.startswith("ge20nn01enus")
    assert fp.split("_")[1] == hashlib.sha256(b"user-agent").hexdigest()[:12]


@pytest.mark.parametrize(
    "method, code",
    [
        ("GET", "ge"), ("PUT", "pu"), ("POST", "po"), ("HEAD", "he"),
        ("DELETE", "de"), ("OPTIONS", "op"), ("PATCH", "pa"),
        ("TRACE", "tr"), ("CONNECT", "co"),
    ],
)
def test_ja4h_method_codes(method, code):
    req = {
        "method": method,
        "version": "HTTP/1.1",
        "headers": [],
        "cookie": None,
        "referer": None,
        "language": None,
        "header_count": 0,
    }
    assert ja4h(req).startswith(code + "11")


def test_ja4h_cookie_values_sorted_independently():
    req = {
        "method": "GET",
        "version": "HTTP/1.1",
        "headers": [("Cookie", "b=2; a=1")],
        "cookie": "b=2; a=1",
        "referer": None,
        "language": None,
        "header_count": 0,
    }
    fp = ja4h(req)
    assert fp.split("_")[2] == hashlib.sha256(b"a,b").hexdigest()[:12]
    assert fp.split("_")[3] == hashlib.sha256(b"a=1,b=2").hexdigest()[:12]
