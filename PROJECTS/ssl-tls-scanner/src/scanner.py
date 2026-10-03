"""Assess a TLS endpoint: protocols, ciphers, certificate chain, and headers.

The scanner opens a verified connection first and, when the certificate does not
validate, re-opens the same connection without verification so the certificate
can still be read and reported. It then probes each TLS protocol version, looks
for weak cipher families the server will accept, walks the full certificate
chain, checks hostname matching and forward secrecy, fetches the HTTPS response
headers for HSTS, and derives a letter grade from the checks that were actually
performed. Standard library only.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import socket
import ssl
import warnings
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Certificate time and formatting helpers
# ---------------------------------------------------------------------------

def parse_certificate_time(value: str | None) -> str | None:
    """Convert certificate time text to ISO format."""

    if not value:
        return None
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), timezone.utc).isoformat()

def certificate_subject(cert: dict[str, Any]) -> str:
    """Format the certificate subject of a getpeercert() dictionary."""

    parts = [
        f"{key}={value}"
        for group in cert.get("subject", ())
        for key, value in group
    ]
    return ", ".join(parts) or "Unavailable"

def certificate_issuer(cert: dict[str, Any]) -> str:
    """Format the certificate issuer of a getpeercert() dictionary."""

    parts = [
        f"{key}={value}"
        for group in cert.get("issuer", ())
        for key, value in group
    ]
    return ", ".join(parts) or "Unavailable"

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def port_number(value: Any) -> int:
    """Validate a TCP port so an out-of-range value cannot reach the socket."""

    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Port must be a whole number, got {value!r}") from exc
    if not 0 <= port <= 65535:
        raise ValueError(f"Port must be between 0 and 65535, got {port}")
    return port

def timeout_seconds(value: Any) -> float:
    """Validate a connection timeout in seconds."""

    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Timeout must be a number of seconds, got {value!r}") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError(f"Timeout must be a positive number of seconds, got {value!r}")
    return timeout

def port_argument(value: str) -> int:
    """Argument parser type for --port."""

    try:
        return port_number(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc

def timeout_argument(value: str) -> float:
    """Argument parser type for --timeout."""

    try:
        return timeout_seconds(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc

# ---------------------------------------------------------------------------
# Minimal DER reader (enough to read an X.509 certificate)
# ---------------------------------------------------------------------------

def _der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER tag-length-value and return (tag, value, next offset)."""

    if offset >= len(data):
        raise ValueError("truncated DER value")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("truncated DER length")
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, data[offset:end], end

def _der_children(value: bytes) -> list[tuple[int, bytes]]:
    """Split a constructed DER value into its child tag-length-value items."""

    items: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(value):
        tag, child, offset = _der_tlv(value, offset)
        items.append((tag, child))
    return items

def _der_oid(value: bytes) -> str:
    """Decode an OBJECT IDENTIFIER into dotted-decimal form."""

    if not value:
        return ""
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    number = 0
    for byte in value[1:]:
        number = (number << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(number))
            number = 0
    return ".".join(parts)

def _der_integer(value: bytes) -> int:
    """Decode a DER INTEGER, honouring the sign bit."""

    return int.from_bytes(value, "big", signed=True)

def _der_bit_string(value: bytes) -> bytes:
    """Strip the leading unused-bits octet from a BIT STRING."""

    return value[1:] if value else value

def _der_string(tag: int, value: bytes) -> str:
    """Decode the common directory-string types."""

    if tag == 0x1E:
        return value.decode("utf-16-be", "replace")
    if tag == 0x14:
        return value.decode("latin-1", "replace")
    if tag == 0x0C:
        return value.decode("utf-8", "replace")
    return value.decode("ascii", "replace")

def _der_time(tag: int, value: bytes) -> str:
    """Decode UTCTime or GeneralizedTime into an ISO 8601 UTC string."""

    text = value.decode("ascii").strip()
    if text.endswith("Z"):
        text = text[:-1]
    if "." in text:
        text = text.split(".", 1)[0]
    if tag == 0x17:
        fmt = "%y%m%d%H%M%S" if len(text) >= 12 else "%y%m%d%H%M"
    else:
        fmt = "%Y%m%d%H%M%S" if len(text) >= 14 else "%Y%m%d%H%M"
    moment = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
    return moment.isoformat()

# Name attribute OIDs, mapped to the short labels used by Python's ssl module.
_NAME_OIDS = {
    "2.5.4.3": "commonName",
    "2.5.4.4": "surname",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "countryName",
    "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName",
    "2.5.4.12": "title",
    "2.5.4.42": "givenName",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "domainComponent",
}

def _parse_name(value: bytes) -> str:
    """Format an X.509 Name (RDNSequence) as ``key=value`` pairs."""

    parts: list[str] = []
    for _set_tag, rdn in _der_children(value):
        for _seq_tag, attribute in _der_children(rdn):
            fields = _der_children(attribute)
            if len(fields) < 2:
                continue
            oid = _der_oid(fields[0][1])
            parts.append(f"{_NAME_OIDS.get(oid, oid)}={_der_string(fields[1][0], fields[1][1])}")
    return ", ".join(parts)

# Public-key algorithm OIDs and the bit size of the fixed-width curves.
_KEY_ALGORITHMS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.10": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.3.101.110": "X25519",
    "1.3.101.111": "X448",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}
_CURVE_BITS = {
    "1.2.840.10045.3.1.7": 256,   # prime256v1 / secp256r1
    "1.3.132.0.34": 384,          # secp384r1
    "1.3.132.0.35": 521,          # secp521r1
    "1.3.132.0.10": 256,          # secp256k1
    "1.2.840.10045.3.1.1": 163,   # sect163k1
}
_FIXED_KEY_BITS = {"Ed25519": 256, "Ed448": 448, "X25519": 256, "X448": 448}

# Signature algorithm OIDs mapped to (family, hash).
_SIGNATURE_ALGORITHMS = {
    "1.2.840.113549.1.1.4": ("RSA", "MD5"),
    "1.2.840.113549.1.1.5": ("RSA", "SHA-1"),
    "1.2.840.113549.1.1.11": ("RSA", "SHA-256"),
    "1.2.840.113549.1.1.12": ("RSA", "SHA-384"),
    "1.2.840.113549.1.1.13": ("RSA", "SHA-512"),
    "1.2.840.113549.1.1.14": ("RSA", "SHA-1"),
    "1.2.840.113549.1.1.15": ("RSA", "SHA-512"),
    "1.2.840.113549.1.1.10": ("RSA", "RSASSA-PSS"),
    "1.2.840.10045.4.1": ("ECDSA", "SHA-1"),
    "1.2.840.10045.4.3.2": ("ECDSA", "SHA-256"),
    "1.2.840.10045.4.3.3": ("ECDSA", "SHA-384"),
    "1.2.840.10045.4.3.4": ("ECDSA", "SHA-512"),
    "1.3.101.112": ("Ed25519", "-"),
    "1.3.101.113": ("Ed448", "-"),
}
_WEAK_SIGNATURE_HASHES = {"SHA-1", "MD5"}

_SAN_OID = "2.5.29.17"

@dataclass(frozen=True)
class CertificateInfo:
    """The fields the scanner reads from one X.509 certificate."""

    subject: str
    issuer: str
    serial_number: str
    not_before: str | None
    not_after: str | None
    key_type: str
    key_size: int | None
    signature_algorithm: str
    signature_hash: str
    weak_signature: bool
    subject_alt_names: tuple[tuple[str, str], ...]
    self_signed: bool

def _parse_san(octet_string: bytes) -> tuple[tuple[str, str], ...]:
    """Decode a subjectAltName extension value into (type, value) pairs."""

    names: list[tuple[str, str]] = []
    tag, sequence, _ = _der_tlv(octet_string, 0)
    if tag != 0x30:
        return tuple(names)
    for name_tag, name_value in _der_children(sequence):
        if name_tag == 0x82:
            names.append(("DNS", name_value.decode("ascii", "replace")))
        elif name_tag == 0x87:
            try:
                names.append(("IP", str(ipaddress.ip_address(name_value))))
            except ValueError:
                names.append(("IP", name_value.hex()))
        elif name_tag == 0x81:
            names.append(("email", name_value.decode("ascii", "replace")))
        elif name_tag == 0x86:
            names.append(("URI", name_value.decode("ascii", "replace")))
    return tuple(names)

def _parse_extensions(children: list[tuple[int, bytes]]) -> tuple[tuple[str, str], ...]:
    """Return the subjectAltName entries from a TBSCertificate extension block."""

    for tag, value in children:
        if tag != 0xA3:
            continue
        _seq_tag, sequence, _ = _der_tlv(value, 0)
        for _ext_tag, extension in _der_children(sequence):
            fields = _der_children(extension)
            if not fields:
                continue
            oid = _der_oid(fields[0][1])
            octets = next((field for field_tag, field in fields if field_tag == 0x04), None)
            if oid == _SAN_OID and octets is not None:
                return _parse_san(octets)
    return ()

def _key_details(algorithm: list[tuple[int, bytes]], public_key: bytes) -> tuple[str, int | None]:
    """Return (key type, key size in bits) from a SubjectPublicKeyInfo."""

    algorithm_oid = _der_oid(algorithm[0][1])
    key_type = _KEY_ALGORITHMS.get(algorithm_oid, algorithm_oid)
    if key_type == "RSA":
        try:
            _seq_tag, rsa_sequence, _ = _der_tlv(public_key, 0)
            modulus = _der_children(rsa_sequence)[0][1]
            return key_type, _der_integer(modulus).bit_length()
        except (ValueError, IndexError):
            return key_type, None
    if key_type == "EC":
        if len(algorithm) > 1 and algorithm[1][0] == 0x06:
            curve_oid = _der_oid(algorithm[1][1])
            return key_type, _CURVE_BITS.get(curve_oid)
        return key_type, None
    return key_type, _FIXED_KEY_BITS.get(key_type)

def parse_certificate(der: bytes) -> CertificateInfo:
    """Parse one DER-encoded X.509 certificate into the fields the scanner reports."""

    _tag, certificate, _ = _der_tlv(der, 0)
    certificate_fields = _der_children(certificate)
    if len(certificate_fields) < 3:
        raise ValueError("not a certificate")
    tbs = certificate_fields[0][1]
    signature_algorithm = certificate_fields[1][1]

    fields = _der_children(tbs)
    index = 0
    if fields and fields[0][0] == 0xA0:
        index = 1
    serial = _der_integer(fields[index][1])
    index += 2  # skip serialNumber and the inner signature AlgorithmIdentifier
    issuer = _parse_name(fields[index][1])
    index += 1
    validity = _der_children(fields[index][1])
    index += 1
    not_before = _der_time(validity[0][0], validity[0][1])
    not_after = _der_time(validity[1][0], validity[1][1])
    subject = _parse_name(fields[index][1])
    index += 1
    spki = _der_children(fields[index][1])
    algorithm = _der_children(spki[0][1])
    key_type, key_size = _key_details(algorithm, _der_bit_string(spki[1][1]))

    signature_fields = _der_children(signature_algorithm)
    signature_oid = _der_oid(signature_fields[0][1])
    family, digest = _SIGNATURE_ALGORITHMS.get(signature_oid, (signature_oid, "-"))
    signature_name = f"{family}/{digest}" if digest != "-" else family

    serial_text = ":".join(f"{byte:02X}" for byte in serial.to_bytes(max(1, (serial.bit_length() + 7) // 8), "big"))

    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        serial_number=serial_text,
        not_before=not_before,
        not_after=not_after,
        key_type=key_type,
        key_size=key_size,
        signature_algorithm=signature_name,
        signature_hash=digest,
        weak_signature=digest in _WEAK_SIGNATURE_HASHES,
        subject_alt_names=_parse_extensions(fields[index:]),
        self_signed=subject == issuer,
    )

# ---------------------------------------------------------------------------
# Cipher classification and forward secrecy
# ---------------------------------------------------------------------------

_WEAK_FAMILY_ORDER = ("RC4", "3DES", "DES", "NULL", "EXPORT", "anonymous", "MD5")

def cipher_families(name: str) -> list[str]:
    """Return the weak cipher families a suite name belongs to (empty if none)."""

    upper = name.upper()
    families: list[str] = []
    if "RC4" in upper:
        families.append("RC4")
    if "3DES" in upper or "DES-CBC3" in upper:
        families.append("3DES")
    elif "DES" in upper:
        families.append("DES")
    if "NULL" in upper:
        families.append("NULL")
    if "EXP" in upper:
        families.append("EXPORT")
    if "ADH" in upper or "AECDH" in upper or "ANON" in upper:
        families.append("anonymous")
    if "MD5" in upper:
        families.append("MD5")
    return families

def cipher_is_forward_secret(name: str | None, tls_version: str | None) -> bool:
    """Whether the negotiated cipher uses an ephemeral (EC)DHE key exchange."""

    if not name:
        return False
    upper = name.upper()
    if upper.startswith("TLS_"):
        # Every TLS 1.3 suite is used with an ephemeral key exchange by default.
        return True
    return any(marker in upper for marker in ("ECDHE", "DHE", "EDH", "EECDH"))

# ---------------------------------------------------------------------------
# Hostname matching (RFC 6125-style, single-label wildcards)
# ---------------------------------------------------------------------------

def _dns_name_matches(host: str, pattern: str) -> bool:
    """Match one DNS name against one certificate pattern."""

    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if host.endswith("." + suffix):
            label = host[: -(len(suffix) + 1)]
            return bool(label) and "." not in label
    return False

def hostname_matches(
    host: str,
    subject_alt_names: tuple[tuple[str, str], ...] | list[tuple[str, str]],
    common_name: str | None = None,
) -> bool:
    """Whether a certificate identity matches the requested hostname."""

    target = host.rstrip(".").lower()
    dns_names = [value for kind, value in subject_alt_names if kind == "DNS"]
    ip_names = [value for kind, value in subject_alt_names if kind == "IP"]
    try:
        requested_ip = ipaddress.ip_address(target)
    except ValueError:
        requested_ip = None
    if requested_ip is not None:
        return any(_same_ip(requested_ip, name) for name in ip_names)
    candidates = dns_names or ([common_name] if common_name else [])
    return any(_dns_name_matches(target, candidate.rstrip(".").lower()) for candidate in candidates)

def _same_ip(requested: ipaddress._BaseAddress, text: str) -> bool:
    """Compare a requested IP address with an IP subjectAltName value."""

    try:
        return requested == ipaddress.ip_address(text)
    except ValueError:
        return False

# ---------------------------------------------------------------------------
# Expiry and grading
# ---------------------------------------------------------------------------

_EXPIRY_CRITICAL_DAYS = 7
_EXPIRY_WARNING_DAYS = 30

def days_until(not_after: str | None, now: datetime | None = None) -> float | None:
    """Whole days from now until a certificate's notAfter time."""

    if not not_after:
        return None
    moment = now or datetime.now(timezone.utc)
    remaining = datetime.fromisoformat(not_after) - moment
    return remaining.total_seconds() / 86400

def expiry_status(days: float | None) -> str:
    """Classify remaining validity into ok / warning / critical / expired."""

    if days is None:
        return "unknown"
    if days < 0:
        return "expired"
    if days <= _EXPIRY_CRITICAL_DAYS:
        return "critical"
    if days <= _EXPIRY_WARNING_DAYS:
        return "warning"
    return "ok"

_HSTS_MIN_MAX_AGE = 15552000  # 180 days

def grade_assessment(assessment: dict[str, Any]) -> dict[str, Any]:
    """Derive a letter grade and its reasons from the checks that were performed.

    The grade only reflects the checks this scanner runs. It is not a complete
    audit: see the README for what it does and does not mean.
    """

    deductions: list[tuple[int, str]] = []
    not_checked: list[str] = []

    protocols = assessment.get("protocols", {})
    for version, result in protocols.items():
        if not result.get("probe_performed", False):
            not_checked.append(f"{version} support could not be probed")
        elif result.get("accepted") and result.get("deprecated"):
            deductions.append((25, f"{version} is accepted although it is deprecated"))

    negotiated = assessment.get("cipher")
    negotiated_families = cipher_families(negotiated) if negotiated else []
    if negotiated_families:
        deductions.append((30, f"negotiated cipher {negotiated} is weak ({', '.join(negotiated_families)})"))

    for entry in assessment.get("offered_weak_ciphers", []):
        if entry.get("probe_performed") and entry.get("supported"):
            deductions.append((10, f"server accepts {entry['family']} cipher suites"))

    certificate = assessment.get("certificate") or {}
    status = certificate.get("expiry_status")
    days = certificate.get("days_until_expiry")
    if status == "expired":
        deductions.append((40, "certificate has expired"))
    elif status == "critical":
        deductions.append((15, f"certificate expires in {days:.1f} days"))
    elif status == "warning":
        deductions.append((8, f"certificate expires in {days:.1f} days"))
    if status == "unknown":
        not_checked.append("certificate expiry could not be read")

    key_type = certificate.get("key_type")
    key_size = certificate.get("key_size")
    if key_size is None:
        not_checked.append("public key size could not be read")
    elif key_type == "RSA" and key_size < 2048:
        deductions.append((20, f"RSA key is only {key_size} bits"))
    elif key_type == "EC" and key_size < 256:
        deductions.append((10, f"EC key is only {key_size} bits"))

    if certificate.get("weak_signature"):
        deductions.append((20, f"certificate is signed with {certificate.get('signature_algorithm')}"))

    if assessment.get("self_signed"):
        deductions.append((30, "certificate is self-signed"))
    elif assessment.get("chain_valid") is False:
        deductions.append((30, "certificate chain did not validate"))

    if assessment.get("hostname_matches") is False:
        deductions.append((30, "certificate does not match the requested hostname"))
    elif assessment.get("hostname_matches") is None:
        not_checked.append("hostname match could not be evaluated")

    if assessment.get("forward_secrecy") is False:
        deductions.append((15, "negotiated cipher has no forward secrecy"))

    hsts = assessment.get("hsts") or {}
    if not hsts.get("checked"):
        not_checked.append("HSTS headers were not retrieved")
    elif not hsts.get("present"):
        deductions.append((5, "no Strict-Transport-Security header"))
    elif hsts.get("max_age") is not None and hsts["max_age"] < _HSTS_MIN_MAX_AGE:
        deductions.append((5, f"Strict-Transport-Security max-age is short ({hsts['max_age']}s)"))

    score = max(0, 100 - sum(points for points, _ in deductions))
    if score >= 90:
        letter = "A"
    elif score >= 80:
        letter = "B"
    elif score >= 70:
        letter = "C"
    elif score >= 60:
        letter = "D"
    else:
        letter = "F"

    return {
        "letter": letter,
        "score": score,
        "reasons": [f"{reason} (-{points})" for points, reason in deductions],
        "not_checked": not_checked,
    }

# ---------------------------------------------------------------------------
# Connection-level checks
# ---------------------------------------------------------------------------

def _unverified_context() -> ssl.SSLContext:
    """A client context that accepts any certificate, for reading identities."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

def _chain_der(tls_socket: ssl.SSLSocket) -> list[bytes]:
    """Return the DER bytes of every certificate the server presented."""

    chain: list[Any] = []
    for getter in ("get_unverified_chain", "get_verified_chain"):
        method = getattr(tls_socket, getter, None)
        if method is None:
            continue
        try:
            chain = method() or []
        except (ssl.SSLError, ValueError):
            chain = []
        if chain:
            break
    der = [bytes(item) for item in chain if isinstance(item, (bytes, bytearray))]
    if not der:
        leaf = tls_socket.getpeercert(binary_form=True)
        if leaf:
            der = [leaf]
    return der

def _handshake(host: str, port: int, timeout: float, context: ssl.SSLContext) -> tuple[list[bytes], str | None, str | None]:
    """Open one TLS connection and read the chain, version, and cipher."""

    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            cipher = tls_socket.cipher()
            return _chain_der(tls_socket), tls_socket.version(), (cipher[0] if cipher else None)

def _main_handshake(host: str, port: int, timeout: float) -> tuple[list[bytes], str | None, str | None, bool, str | None]:
    """Connect with verification, falling back to an unverified read on failure."""

    try:
        chain, version, cipher = _handshake(host, port, timeout, ssl.create_default_context())
        return chain, version, cipher, True, None
    except ssl.SSLCertVerificationError as exc:
        error = str(exc)
    chain, version, cipher = _handshake(host, port, timeout, _unverified_context())
    return chain, version, cipher, False, error

_PROTOCOL_PROBES = (
    ("TLSv1.0", "TLSv1", True),
    ("TLSv1.1", "TLSv1_1", True),
    ("TLSv1.2", "TLSv1_2", False),
    ("TLSv1.3", "TLSv1_3", False),
)

def probe_protocol(host: str, port: int, timeout: float, version_name: str, deprecated: bool) -> dict[str, Any]:
    """Attempt a handshake restricted to one protocol version."""

    result: dict[str, Any] = {"accepted": False, "deprecated": deprecated, "probe_performed": False, "error": None}
    version = getattr(ssl.TLSVersion, version_name, None)
    if version is None:
        result["error"] = f"client library has no {version_name}"
        return result
    context = _unverified_context()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            context.minimum_version = version
            context.maximum_version = version
        except (ValueError, ssl.SSLError) as exc:
            result["error"] = f"client library cannot restrict to {version_name}: {exc}"
            return result
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    result["probe_performed"] = True
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                result["accepted"] = True
                result["negotiated"] = tls_socket.version()
    except (OSError, ssl.SSLError, ValueError) as exc:
        result["error"] = str(exc)
    return result

def probe_weak_cipher_families(host: str, port: int, timeout: float) -> list[dict[str, Any]]:
    """Try to negotiate each weak cipher family the client library can offer."""

    catalog = _unverified_context()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            catalog.maximum_version = ssl.TLSVersion.TLSv1_2
        except (ValueError, ssl.SSLError):
            pass
    try:
        catalog.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    available: dict[str, list[str]] = {}
    for cipher in catalog.get_ciphers():
        for family in cipher_families(cipher["name"]):
            available.setdefault(family, []).append(cipher["name"])

    results: list[dict[str, Any]] = []
    for family in _WEAK_FAMILY_ORDER:
        names = available.get(family)
        if not names:
            results.append({
                "family": family, "supported": False, "probe_performed": False,
                "error": "client library offers no cipher in this family",
            })
            continue
        context = _unverified_context()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            try:
                context.maximum_version = ssl.TLSVersion.TLSv1_2
            except (ValueError, ssl.SSLError):
                pass
        try:
            context.set_ciphers(":".join(names) + ":@SECLEVEL=0")
        except ssl.SSLError as exc:
            results.append({
                "family": family, "supported": False, "probe_performed": False,
                "error": f"could not select family ciphers: {exc}",
            })
            continue
        entry: dict[str, Any] = {"family": family, "supported": False, "probe_performed": True, "error": None}
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                    cipher = tls_socket.cipher()
                    entry["supported"] = True
                    entry["cipher"] = cipher[0] if cipher else None
        except (OSError, ssl.SSLError, ValueError) as exc:
            entry["error"] = str(exc)
        results.append(entry)
    return results

def fetch_hsts(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Fetch the HTTPS response headers and read Strict-Transport-Security."""

    result: dict[str, Any] = {"checked": False, "present": False, "max_age": None,
                              "include_subdomains": False, "preload": False, "raw": None}
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with _unverified_context().wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                tls_socket.settimeout(timeout)
                request = (
                    f"HEAD / HTTP/1.1\r\nHost: {host}\r\n"
                    "User-Agent: ssl-tls-scanner\r\nConnection: close\r\n\r\n"
                )
                tls_socket.sendall(request.encode("ascii"))
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = tls_socket.recv(4096)
                    if not chunk:
                        break
                    data += chunk
    except (OSError, ssl.SSLError, ValueError) as exc:
        result["error"] = str(exc)
        return result

    result["checked"] = True
    header_block = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    for line in header_block.split("\r\n")[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "strict-transport-security":
            result["present"] = True
            result["raw"] = value.strip()
            lowered = value.lower()
            for directive in lowered.split(";"):
                directive = directive.strip()
                if directive.startswith("max-age="):
                    digits = directive.split("=", 1)[1].strip().strip('"')
                    result["max_age"] = int(digits) if digits.isdigit() else None
                elif directive == "includesubdomains":
                    result["include_subdomains"] = True
                elif directive == "preload":
                    result["preload"] = True
    return result

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _leaf_summary(certificate: CertificateInfo, now: datetime | None = None) -> dict[str, Any]:
    """Add the derived expiry fields to a parsed leaf certificate."""

    summary = asdict(certificate)
    remaining = days_until(certificate.not_after, now)
    summary["days_until_expiry"] = remaining
    summary["expiry_status"] = expiry_status(remaining)
    return summary

def scan(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """Assess a TLS endpoint and return every field the scanner can read."""

    port = port_number(port)
    timeout = timeout_seconds(timeout)

    chain_der, tls_version, cipher, chain_valid, verify_error = _main_handshake(host, port, timeout)
    if not chain_der:
        raise ssl.SSLError("server presented no certificate")

    certificates = [parse_certificate(der) for der in chain_der]
    leaf = certificates[0]

    protocols = {
        label: probe_protocol(host, port, timeout, name, deprecated)
        for label, name, deprecated in _PROTOCOL_PROBES
    }
    offered_weak = probe_weak_cipher_families(host, port, timeout)
    hsts = fetch_hsts(host, port, timeout)

    common_name = None
    for key, value in (part.split("=", 1) for part in leaf.subject.split(", ") if "=" in part):
        if key == "commonName":
            common_name = value
            break
    if leaf.subject_alt_names:
        matches = hostname_matches(host, leaf.subject_alt_names)
    elif common_name:
        matches = hostname_matches(host, (), common_name)
    else:
        matches = None

    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "tls_version": tls_version,
        "cipher": cipher,
        "certificate_subject": leaf.subject,
        "certificate_issuer": leaf.issuer,
        "certificate_expires": leaf.not_after,
        "protocols": protocols,
        "cipher_weaknesses": cipher_families(cipher) if cipher else [],
        "offered_weak_ciphers": offered_weak,
        "forward_secrecy": cipher_is_forward_secret(cipher, tls_version),
        "certificate": _leaf_summary(leaf),
        "certificate_chain": [asdict(certificate) for certificate in certificates],
        "self_signed": leaf.self_signed,
        "chain_valid": chain_valid,
        "chain_error": verify_error,
        "hostname_matches": matches,
        "hsts": hsts,
    }
    result["grade"] = grade_assessment(result)
    return result

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _format_protocols(protocols: dict[str, dict[str, Any]]) -> list[str]:
    """Render the protocol probe results."""

    lines = []
    for version, result in protocols.items():
        if not result.get("probe_performed"):
            state = "not probed"
        elif result.get("accepted"):
            state = "accepted"
        else:
            state = "rejected"
        suffix = " (deprecated)" if result.get("deprecated") else ""
        lines.append(f"  {version}: {state}{suffix}")
    return lines

def format_result(result: dict[str, Any]) -> str:
    """Render a scan result as readable text."""

    lines = [
        f"host: {result['host']}",
        f"port: {result['port']}",
        f"tls_version: {result['tls_version']}",
        f"cipher: {result['cipher']}",
        f"forward_secrecy: {result['forward_secrecy']}",
        f"certificate_subject: {result['certificate_subject']}",
        f"certificate_issuer: {result['certificate_issuer']}",
        f"certificate_expires: {result['certificate_expires']}",
        "",
        "protocols:",
    ]
    lines.extend(_format_protocols(result["protocols"]))
    lines.append("")
    weaknesses = result["cipher_weaknesses"]
    lines.append(f"cipher_weaknesses: {', '.join(weaknesses) if weaknesses else 'none'}")
    accepted = [entry["family"] for entry in result["offered_weak_ciphers"]
                if entry.get("probe_performed") and entry.get("supported")]
    lines.append(f"offered_weak_ciphers: {', '.join(accepted) if accepted else 'none detected'}")
    lines.append("")
    chain = result["certificate_chain"]
    lines.append(f"certificate_chain: {len(chain)} certificate(s)")
    for index, certificate in enumerate(chain):
        lines.append(
            f"  [{index}] subject={certificate['subject']} | issuer={certificate['issuer']} | "
            f"key={certificate['key_type']} {certificate['key_size']} | "
            f"signature={certificate['signature_algorithm']} | expires={certificate['not_after']}"
        )
    lines.append("")
    leaf = result["certificate"]
    lines.append("certificate:")
    lines.append(f"  key_type: {leaf['key_type']}")
    lines.append(f"  key_size: {leaf['key_size']}")
    lines.append(f"  signature_algorithm: {leaf['signature_algorithm']}")
    names = ", ".join(value for _kind, value in leaf["subject_alt_names"])
    lines.append(f"  subject_alt_names: {names or 'none'}")
    lines.append(f"  days_until_expiry: {leaf['days_until_expiry']:.1f}" if leaf["days_until_expiry"] is not None
                 else "  days_until_expiry: unknown")
    lines.append(f"  expiry_status: {leaf['expiry_status']}")
    lines.append(f"  self_signed: {result['self_signed']}")
    lines.append(f"  chain_valid: {result['chain_valid']}")
    lines.append(f"  hostname_matches: {result['hostname_matches']}")
    lines.append("")
    hsts = result["hsts"]
    lines.append("hsts:")
    lines.append(f"  checked: {hsts['checked']}")
    lines.append(f"  present: {hsts['present']}")
    lines.append(f"  max_age: {hsts['max_age']}")
    lines.append(f"  include_subdomains: {hsts['include_subdomains']}")
    lines.append("")
    grade = result["grade"]
    lines.append(f"grade: {grade['letter']} (score {grade['score']})")
    for reason in grade["reasons"]:
        lines.append(f"  - {reason}")
    for note in grade["not_checked"]:
        lines.append(f"  not checked: {note}")
    return "\n".join(lines)

def main() -> None:
    """Assess a TLS endpoint and print the result."""

    parser = argparse.ArgumentParser(description="Assess a TLS connection safely.")
    parser.add_argument("host")
    parser.add_argument("--port", type=port_argument, default=443)
    parser.add_argument("--timeout", type=timeout_argument, default=5.0)
    parser.add_argument("--json", action="store_true", help="print the full assessment as JSON")
    args = parser.parse_args()

    try:
        result = scan(args.host, args.port, args.timeout)
    except (OSError, ssl.SSLError, ValueError, OverflowError) as exc:
        raise SystemExit(f"TLS assessment failed: {exc}") from exc

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(format_result(result))

if __name__ == "__main__":
    main()
