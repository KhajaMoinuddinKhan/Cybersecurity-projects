"""Weak cipher families and forward secrecy are decided from the suite name."""
import pytest

from src.scanner import cipher_families, cipher_is_forward_secret

@pytest.mark.parametrize(
    "name, expected",
    [
        ("TLS_AES_256_GCM_SHA384", []),
        ("ECDHE-RSA-AES256-GCM-SHA384", []),
        ("RC4-SHA", ["RC4"]),
        ("ECDHE-RSA-RC4-SHA", ["RC4"]),
        ("DES-CBC3-SHA", ["3DES"]),
        ("ECDHE-RSA-DES-CBC3-SHA", ["3DES"]),
        ("DES-CBC-SHA", ["DES"]),
        ("NULL-SHA", ["NULL"]),
        ("ECDHE-RSA-NULL-SHA", ["NULL"]),
        ("EXP-RC4-MD5", ["RC4", "EXPORT", "MD5"]),
        ("ADH-AES128-SHA", ["anonymous"]),
        ("AECDH-AES256-SHA", ["anonymous"]),
        ("DES-CBC3-MD5", ["3DES", "MD5"]),
    ],
)
def test_cipher_families_are_classified(name, expected):
    assert cipher_families(name) == expected

@pytest.mark.parametrize(
    "name, version, expected",
    [
        ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", True),
        ("DHE-RSA-AES256-GCM-SHA384", "TLSv1.2", True),
        ("AES128-SHA", "TLSv1.2", False),
        ("TLS_AES_256_GCM_SHA384", "TLSv1.3", True),
        (None, "TLSv1.2", False),
    ],
)
def test_forward_secrecy_from_the_key_exchange(name, version, expected):
    assert cipher_is_forward_secret(name, version) is expected
