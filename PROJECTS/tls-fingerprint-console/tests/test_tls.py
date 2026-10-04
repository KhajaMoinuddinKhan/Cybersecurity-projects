"""Round-trip tests for the TLS / TCP / HTTP parsers."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fixtures import make_pcap  # noqa: E402
from src.pcap import read_pcap, reassemble_streams  # noqa: E402
from src.tls import (  # noqa: E402
    ECH_EXTENSION,
    fingerprint_caveat,
    is_ech,
    iter_tls_records,
    parse_certificate_message,
    parse_client_hello,
    parse_http_request,
    parse_server_hello,
    parse_tcp_syn,
)


def test_iter_tls_records_single():
    records = iter_tls_records(make_pcap.build_client_hello_record())
    assert len(records) == 1
    assert records[0]["record_type"] == 22
    assert records[0]["version"] == 0x0301
    assert records[0]["body"][0] == 1  # handshake type: ClientHello


def test_iter_tls_records_multiple_and_truncated():
    sh = make_pcap.build_server_hello_record()
    cert = make_pcap.build_certificate_record()
    records = iter_tls_records(sh + cert)
    assert [r["record_type"] for r in records] == [22, 22]

    # a full record followed by a truncated one: stop cleanly, keep the full one
    records = iter_tls_records(sh + b"\x16\x03\x03\x00\xff\x00\x01")
    assert len(records) == 1
    assert records[0]["body"] == iter_tls_records(sh)[0]["body"]

    # trailing garbage shorter than a record header: no records
    assert iter_tls_records(b"\x16\x03") == []


def test_parse_client_hello_exact_fields():
    record = iter_tls_records(make_pcap.build_client_hello_record())[0]
    hello = parse_client_hello(record["body"])
    assert hello["version"] == 0x0303
    assert hello["session_id"] == make_pcap.CLIENT_HELLO_SESSION_ID
    assert hello["ciphers"] == make_pcap.CLIENT_HELLO_CIPHERS
    assert hello["extensions"] == make_pcap.CLIENT_HELLO_EXTENSIONS
    assert hello["sni"] == make_pcap.CLIENT_HELLO_SNI
    assert hello["alpn"] == make_pcap.CLIENT_HELLO_ALPN
    assert hello["curves"] == make_pcap.CLIENT_HELLO_CURVES
    assert hello["point_formats"] == make_pcap.CLIENT_HELLO_POINT_FORMATS
    assert hello["sig_algs"] == make_pcap.CLIENT_HELLO_SIG_ALGS
    assert hello["supported_versions"] == make_pcap.CLIENT_HELLO_VERSIONS
    assert hello["grease"] == make_pcap.CLIENT_HELLO_GREASE
    # wire order preserved, grease still present
    assert 0x0A0A in hello["ciphers"]
    assert 0x1A1A in hello["extensions"]


def test_parse_client_hello_bare_body():
    hello = parse_client_hello(make_pcap.build_client_hello_body())
    assert hello["sni"] == make_pcap.CLIENT_HELLO_SNI
    assert hello["alpn"] == [b"h2", b"http/1.1"]
    assert hello["grease"] == make_pcap.CLIENT_HELLO_GREASE


def test_parse_server_hello():
    record = iter_tls_records(make_pcap.build_server_hello_record())[0]
    hello = parse_server_hello(record["body"])
    assert hello["version"] == 0x0303
    assert hello["cipher"] == make_pcap.SERVER_HELLO_CIPHER
    assert hello["extensions"] == make_pcap.SERVER_HELLO_EXTENSIONS
    assert hello["alpn"] == make_pcap.SERVER_HELLO_ALPN


def test_parse_certificate_message_tls13():
    der = make_pcap.build_der_certificate()
    body = make_pcap.build_certificate_message_body(tls13=True)
    certs = parse_certificate_message(body)
    assert certs == [der]
    assert certs[0][0] == 0x30
    assert len(certs[0]) == len(der)


def test_parse_certificate_message_tls12():
    der = make_pcap.build_der_certificate()
    body = make_pcap.build_certificate_message_body(tls13=False)
    certs = parse_certificate_message(body)
    assert certs == [der]


def test_parse_certificate_message_from_record():
    record = iter_tls_records(make_pcap.build_certificate_record())[0]
    certs = parse_certificate_message(record["body"])
    assert certs == [make_pcap.build_der_certificate()]


def test_parse_tcp_syn():
    packets = read_pcap(make_pcap.make_classic_pcap())
    syn = [p for p in packets
           if p["protocol"] == "tcp" and "SYN" in p["flags"]
           and "ACK" not in p["flags"]][0]
    data = parse_tcp_syn(syn)
    assert data["window"] == make_pcap.TCP_SYN_WINDOW
    assert data["options"] == make_pcap.TCP_SYN_OPTIONS_KINDS
    assert data["mss"] == make_pcap.TCP_SYN_MSS
    assert data["window_scale"] == make_pcap.TCP_SYN_WINDOW_SCALE


def test_parse_http_request():
    req = parse_http_request(make_pcap.build_http_get())
    assert req["method"] == make_pcap.HTTP_METHOD
    assert req["version"] == make_pcap.HTTP_VERSION
    names = [name for name, _ in req["headers"]]
    assert names[0] == "Host"
    assert len(req["headers"]) == len(make_pcap.HTTP_REQUEST_LINES) - 1
    assert "Cookie" in names and "Referer" in names
    assert req["cookie"] == make_pcap.HTTP_COOKIE
    assert req["referer"] == make_pcap.HTTP_REFERER
    assert req["language"] == make_pcap.HTTP_LANGUAGE
    assert req["header_count"] == make_pcap.HTTP_HEADER_COUNT


def test_client_hello_from_reassembled_pcap():
    packets = read_pcap(make_pcap.make_classic_pcap())
    streams = reassemble_streams(packets)
    client = [s for s in streams if s["src_port"] == make_pcap.TLS_CLIENT_PORT][0]
    records = iter_tls_records(client["payload"])
    assert len(records) == 1
    assert records[0]["record_type"] == 22
    hello = parse_client_hello(records[0]["body"])
    assert hello["sni"] == make_pcap.CLIENT_HELLO_SNI
    assert hello["alpn"] == make_pcap.CLIENT_HELLO_ALPN
    assert hello["ciphers"] == make_pcap.CLIENT_HELLO_CIPHERS
    assert hello["extensions"] == make_pcap.CLIENT_HELLO_EXTENSIONS


def test_server_stream_parses_hello_and_certificate():
    packets = read_pcap(make_pcap.make_classic_pcap())
    streams = reassemble_streams(packets)
    server = [s for s in streams if s["src_port"] == make_pcap.TLS_SERVER_PORT][0]
    records = iter_tls_records(server["payload"])
    assert len(records) == 2
    hello = parse_server_hello(records[0]["body"])
    assert hello["cipher"] == make_pcap.SERVER_HELLO_CIPHER
    certs = parse_certificate_message(records[1]["body"])
    assert certs == [make_pcap.build_der_certificate()]


def test_parse_http_request_rejects_empty():
    with pytest.raises(ValueError):
        parse_http_request(b"\r\n\r\n")


# ------------------------------------------------------------- ECH awareness
def _ech_body(config_id=0x2a):
    """A well-formed outer ECHClientHello extension body."""
    return (b"\x00"                       # ECHClientHelloType: outer
            + b"\x00\x01"                # HpkeSymmetricCipherSuite.kdf_id
            + b"\x00\x01"                # HpkeSymmetricCipherSuite.aead_id
            + bytes([config_id])          # config_id
            + b"\x00\x00"                # enc<0..> length 0
            + b"\x00\x03" + b"abc")      # payload<1..> length 3


def _build_hello_body(exts):
    """Mirror of make_pcap.build_client_hello_body but with caller extensions."""
    random = bytes(range(32))
    session_id = make_pcap.CLIENT_HELLO_SESSION_ID
    ciphers = b"".join(make_pcap._u16(c) for c in make_pcap.CLIENT_HELLO_CIPHERS)
    return (make_pcap._u16(0x0303) + random + make_pcap._u8(len(session_id))
            + session_id + make_pcap._u16(len(ciphers)) + ciphers
            + make_pcap._u8(1) + make_pcap._u8(0)
            + make_pcap._u16(len(exts)) + exts)


def _base_exts():
    return make_pcap._build_client_hello_extensions()


def _exts_with_ech(ech_body):
    return _base_exts() + make_pcap._ext(ECH_EXTENSION, ech_body)


def test_client_hello_without_ech():
    hello = parse_client_hello(_build_hello_body(_base_exts()))
    assert hello["ech"] is False
    assert hello["ech_outer"] is False
    assert hello["ech_config_ids"] == []
    assert is_ech(hello) is False
    assert fingerprint_caveat(hello) is None


def test_client_hello_with_wellformed_ech():
    hello = parse_client_hello(_build_hello_body(_exts_with_ech(_ech_body(0x2a))))
    assert hello["ech"] is True
    assert hello["ech_outer"] is True
    assert hello["ech_config_ids"] == [0x2a]
    assert is_ech(hello) is True
    caveat = fingerprint_caveat(hello)
    assert isinstance(caveat, str) and caveat.strip()
    assert "outer" in caveat.lower()


def test_client_hello_with_truncated_ech_body_does_not_raise():
    hello = parse_client_hello(_build_hello_body(_exts_with_ech(b"\x00\x01")))
    assert hello["ech"] is True
    assert hello["ech_outer"] is False
    assert hello["ech_config_ids"] == []
    assert is_ech(hello) is True
    assert fingerprint_caveat(hello) is not None


def test_client_hello_with_garbage_ech_body_does_not_raise():
    hello = parse_client_hello(_build_hello_body(_exts_with_ech(b"\xff\xff\xff\xff")))
    assert hello["ech"] is True
    assert hello["ech_outer"] is False
    assert hello["ech_config_ids"] == []


def test_client_hello_existing_keys_unchanged_without_ech():
    canonical = parse_client_hello(make_pcap.build_client_hello_body())
    hello = parse_client_hello(_build_hello_body(_base_exts()))
    for key in ("version", "session_id", "ciphers", "extensions", "sni",
                "alpn", "curves", "point_formats", "sig_algs",
                "supported_versions", "grease"):
        assert key in hello
        assert hello[key] == canonical[key]
    assert hello["sni"] == make_pcap.CLIENT_HELLO_SNI
    assert hello["extensions"] == make_pcap.CLIENT_HELLO_EXTENSIONS
    assert hello["grease"] == make_pcap.CLIENT_HELLO_GREASE
