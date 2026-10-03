"""Certificate fields are read straight from the DER bytes of the certificate."""
from __future__ import annotations

import os
import ssl
from datetime import datetime, timezone

from src.scanner import days_until, expiry_status, hostname_matches, parse_certificate

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

def load(name: str):
    pem = open(os.path.join(FIXTURES, name), encoding="ascii").read()
    return parse_certificate(ssl.PEM_cert_to_DER_cert(pem))

def test_self_signed_rsa_certificate_fields():
    info = load("self_signed_rsa_cert.pem")
    assert info.subject == "commonName=localhost"
    assert info.issuer == "commonName=localhost"
    assert info.self_signed is True
    assert info.key_type == "RSA"
    assert info.key_size == 2048
    assert info.signature_algorithm == "RSA/SHA-256"
    assert info.weak_signature is False
    assert ("DNS", "localhost") in info.subject_alt_names
    assert ("IP", "127.0.0.1") in info.subject_alt_names
    assert info.serial_number
    assert info.not_after.endswith("+00:00")

def test_ec_certificate_reports_the_curve_size():
    info = load("self_signed_ec_cert.pem")
    assert info.key_type == "EC"
    assert info.key_size == 256
    assert info.signature_algorithm == "ECDSA/SHA-256"

def test_ca_signed_leaf_is_not_self_signed():
    info = load("leaf_cert.pem")
    assert info.self_signed is False
    assert info.issuer.startswith("commonName=Hermes Test CA")

def test_hostname_matching_rules():
    sans = (("DNS", "example.com"), ("DNS", "*.example.com"), ("IP", "127.0.0.1"))
    assert hostname_matches("example.com", sans)
    assert hostname_matches("www.example.com", sans)
    assert not hostname_matches("a.b.example.com", sans)
    assert not hostname_matches("example.org", sans)
    assert hostname_matches("127.0.0.1", sans)
    assert not hostname_matches("127.0.0.2", sans)

def test_hostname_matching_falls_back_to_common_name():
    assert hostname_matches("legacy.test", (), "legacy.test")
    assert not hostname_matches("other.test", (), "legacy.test")

def test_expiry_bands():
    assert expiry_status(None) == "unknown"
    assert expiry_status(-1) == "expired"
    assert expiry_status(3) == "critical"
    assert expiry_status(20) == "warning"
    assert expiry_status(200) == "ok"

def test_days_until_uses_the_supplied_moment():
    moment = datetime(2030, 1, 1, tzinfo=timezone.utc)
    assert days_until("2030-01-02T00:00:00+00:00", moment) == 1.0
    assert days_until(None) is None

def test_sha1_signature_is_flagged():
    # Rewrite the RSA/SHA-256 signature OID to RSA/SHA-1 in a real certificate's
    # DER. The two OIDs are the same length, so the structure stays valid and the
    # parser must notice the weaker digest.
    pem = open(os.path.join(FIXTURES, "self_signed_rsa_cert.pem"), encoding="ascii").read()
    der = bytearray(ssl.PEM_cert_to_DER_cert(pem))
    sha256_oid = bytes.fromhex("06092A864886F70D01010B")
    sha1_oid = bytes.fromhex("06092A864886F70D010105")
    assert sha256_oid in der
    info = parse_certificate(bytes(der.replace(sha256_oid, sha1_oid)))
    assert info.signature_hash == "SHA-1"
    assert info.signature_algorithm == "RSA/SHA-1"
    assert info.weak_signature is True
