"""JA3 / JA3S TLS client and server fingerprints (Salesforce JA3).

JA3 concatenates the decimal values of the ClientHello fields

    SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat

with ``-`` between values inside a field and ``,`` between fields, then
MD5-hashes the resulting string.  JA3S uses the field order

    SSLVersion,Cipher,SSLExtension

GREASE values (0x0a0a, 0x1a1a, ... 0xfafa) are ignored everywhere so a
GREASE-using client still produces one stable hash.

The ``hello`` dicts are exactly those returned by ``src.tls``: ciphers,
extensions, curves and point_formats arrive in WIRE ORDER and still contain
GREASE.  These functions strip GREASE themselves.
"""

from hashlib import md5

__all__ = ["GREASE", "ja3", "ja3_raw", "ja3s", "ja3s_raw"]

# The 16 GREASE values (RFC 8701 / draft-davidben-tls-grease-01).
GREASE = frozenset(
    {
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
        0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
        0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    }
)


def _no_grease(values):
    """Return ``values`` with every GREASE entry removed, order preserved."""
    if not values:
        return []
    return [value for value in values if value not in GREASE]


def _join(values):
    """Dash-join the decimal representation of ``values``."""
    return "-".join(str(value) for value in values)


def ja3_raw(hello):
    """Return the pre-hash JA3 string for a ClientHello dict."""
    version = hello.get("version")
    ciphers = _join(_no_grease(hello.get("ciphers")))
    extensions = _join(_no_grease(hello.get("extensions")))
    curves = _join(_no_grease(hello.get("curves")))
    point_formats = _join(_no_grease(hello.get("point_formats")))
    return ",".join(
        [str(version), ciphers, extensions, curves, point_formats]
    )


def ja3(hello):
    """Return the 32-character MD5 JA3 fingerprint for a ClientHello dict."""
    return md5(ja3_raw(hello).encode("utf-8")).hexdigest()


def ja3s_raw(hello):
    """Return the pre-hash JA3S string for a ServerHello dict."""
    version = hello.get("version")
    cipher = hello.get("cipher")
    extensions = _join(_no_grease(hello.get("extensions")))
    return ",".join([str(version), str(cipher), extensions])


def ja3s(hello):
    """Return the 32-character MD5 JA3S fingerprint for a ServerHello dict."""
    return md5(ja3s_raw(hello).encode("utf-8")).hexdigest()
