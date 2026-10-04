"""JA4 family fingerprints: JA4, JA4S, JA4X, JA4T and JA4H.

Implements the FoxIO JA4+ specification (technical_details/JA4.md):

    JA4  = <proto><version><sni><cipher-count><ext-count><alpn>
           _<sha256(sorted cipher hex)[:12]>
           _<sha256(sorted ext hex w/o 0000/0010, then _ sig-algs in order)[:12]>
    JA4S = <proto><version><ext-count><alpn>_<chosen cipher hex>
           _<sha256(extensions in arrival order)[:12]>
    JA4X = <sha256(issuer RDN OIDs)[:12]>_<sha256(subject RDN OIDs)[:12]>
           _<sha256(certificate extension OIDs)[:12]>
    JA4T = <window>_<option kinds>-...-<last>_<mss>_<window scale>
    JA4H = <method><version><cookie><referer><hdr-count><lang>
           _<sha256(header names in order)[:12]>
           _<sha256(sorted cookie names)[:12]>
           _<sha256(sorted cookie name=value pairs)[:12]>

GREASE values are ignored everywhere.  ``hello`` dicts are exactly those
returned by ``src.tls``: ciphers/extensions/curves/point_formats/sig_algs
arrive in wire order and still contain GREASE, so these functions strip it
themselves.  Only ``hashlib`` and the standard library are used.
"""

from hashlib import sha256

__all__ = ["GREASE", "ja4", "ja4_r", "ja4s", "ja4x", "ja4t", "ja4h"]

# The 16 GREASE values (RFC 8701 / draft-davidben-tls-grease-01).
GREASE = frozenset(
    {
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
        0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
        0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    }
)

# TLS/DTLS protocol version -> 2-character JA4 code (unknown -> "00").
_TLS_VERSION = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
    0x0002: "s2", 0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}

# HTTP method -> 2-character JA4H code.
_HTTP_METHOD = {
    "GET": "ge", "PUT": "pu", "POST": "po", "HEAD": "he", "DELETE": "de",
    "OPTIONS": "op", "PATCH": "pa", "TRACE": "tr", "CONNECT": "co",
}

_ZERO12 = "000000000000"
_ZERO10 = "0000000000"


def _sha12(text):
    """First 12 hex characters of the lowercase sha256 of ``text``."""
    return sha256(text.encode("utf-8")).hexdigest()[:12]


def _no_grease(values):
    """Return ``values`` without GREASE entries, order preserved."""
    if not values:
        return []
    return [value for value in values if value not in GREASE]


def _hex4(value):
    return "{:04x}".format(value & 0xFFFF)


def _count(values):
    n = len(_no_grease(values))
    return "99" if n > 99 else "{:02d}".format(n)


def _version(hello):
    """JA4 2-char version: highest supported_version, else Protocol Version."""
    supported = _no_grease(hello.get("supported_versions"))
    version = max(supported) if supported else hello.get("version")
    return _TLS_VERSION.get(version, "00")


def _alnum(byte):
    return 0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A


def _alpn_code(alpn):
    """First and last characters of the first ALPN value.

    Empty/missing -> "00"; a single character supplies both ends; when the
    first or last byte is not an ASCII alphanumeric the first and last
    characters of the hex representation are used instead.
    """
    if isinstance(alpn, (list, tuple)):
        first = alpn[0] if alpn else b""
    elif isinstance(alpn, (bytes, bytearray)):
        first = bytes(alpn)
    elif alpn is None:
        first = b""
    else:
        first = str(alpn).encode("latin-1")
    if not first:
        return "00"
    lo, hi = first[0], first[-1]
    if _alnum(lo) and _alnum(hi):
        return chr(lo) + chr(hi)
    text = first.hex()
    return text[0] + text[-1]


def _cipher_preimage(ciphers):
    """Comma-joined lowercase 4-char hex ciphers sorted in hex order."""
    return ",".join(sorted(_hex4(c) for c in _no_grease(ciphers)))


def _ext_preimage(extensions, sig_algs):
    """Sorted extension hex (no SNI/ALPN) plus sig-algs in original order."""
    exts = sorted(
        h for h in (_hex4(e) for e in _no_grease(extensions))
        if h not in ("0000", "0010")
    )
    text = ",".join(exts)
    sigs = ",".join(_hex4(s) for s in _no_grease(sig_algs))
    if sigs:
        text = text + "_" + sigs
    return text


def _a_section(hello, proto):
    sni = "d" if 0x0000 in (hello.get("extensions") or []) else "i"
    return "{}{}{}{}{}{}".format(
        proto,
        _version(hello),
        sni,
        _count(hello.get("ciphers")),
        _count(hello.get("extensions")),
        _alpn_code(hello.get("alpn")),
    )


def ja4(hello, proto="t"):
    """Return the hashed JA4 client fingerprint."""
    a = _a_section(hello, proto)
    b = _cipher_preimage(hello.get("ciphers"))
    b = _sha12(b) if b else _ZERO12
    c = _ext_preimage(hello.get("extensions"), hello.get("sig_algs"))
    c = _sha12(c) if c else _ZERO12
    return "{}_{}_{}".format(a, b, c)


def ja4_r(hello, proto="t"):
    """Return the raw (un-hashed, GREASE-free) JA4 client fingerprint."""
    a = _a_section(hello, proto)
    b = _cipher_preimage(hello.get("ciphers"))
    c = _ext_preimage(hello.get("extensions"), hello.get("sig_algs"))
    return "{}_{}_{}".format(a, b, c)


def ja4s(hello, proto="t"):
    """Return the JA4S server fingerprint."""
    exts = [_hex4(e) for e in _no_grease(hello.get("extensions"))]
    c = _sha12(",".join(exts)) if exts else _ZERO12
    a = "{}{}{}{}".format(
        proto,
        _version(hello),
        _count(hello.get("extensions")),
        _alpn_code(hello.get("alpn")),
    )
    cipher = hello.get("cipher")
    return "{}_{}_{}".format(a, _hex4(cipher if cipher is not None else 0), c)


# ---------------------------------------------------------------------------
# JA4X -- X.509 certificate structure fingerprint (stdlib DER parsing)
# ---------------------------------------------------------------------------

def _read_tlv(data, offset):
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(data[offset:offset + nbytes], "big")
        offset += nbytes
    return tag, data[offset:offset + length], offset + length


def _children(content):
    items = []
    offset = 0
    end = len(content)
    while offset < end:
        tag, value, offset = _read_tlv(content, offset)
        items.append((tag, value))
    return items


def _decode_oid(content):
    if not content:
        return ""
    first = content[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(part) for part in parts)


def _parse_name(content):
    """Ordered list of RDN attribute-type OIDs in a Name/RDNSequence."""
    oids = []
    for tag, rdn in _children(content):
        if tag != 0x31:  # RelativeDistinguishedName is a SET
            continue
        for atag, atv in _children(rdn):
            if atag != 0x30:  # AttributeTypeAndValue is a SEQUENCE
                continue
            parts = _children(atv)
            if parts and parts[0][0] == 0x06:
                oids.append(_decode_oid(parts[0][1]))
    return oids


def _parse_extensions(content):
    """Ordered list of certificate extension OIDs."""
    oids = []
    for tag, seq in _children(content):
        if tag != 0x30:  # Extensions ::= SEQUENCE OF Extension
            continue
        for etag, ext in _children(seq):
            if etag != 0x30:  # Extension ::= SEQUENCE
                continue
            parts = _children(ext)
            if parts and parts[0][0] == 0x06:
                oids.append(_decode_oid(parts[0][1]))
    return oids


def _parse_certificate(der):
    """Walk a DER Certificate and return (issuer_oids, subject_oids, ext_oids)."""
    _, certificate, _ = _read_tlv(bytes(der), 0)
    tbs = _children(certificate)[0][1]
    items = _children(tbs)
    i = 0
    if items and items[i][0] == 0xA0:  # version [0] EXPLICIT
        i += 1
    i += 1  # serialNumber
    i += 1  # signature AlgorithmIdentifier
    issuer = _parse_name(items[i][1])
    i += 1
    i += 1  # validity
    subject = _parse_name(items[i][1])
    i += 1
    i += 1  # subjectPublicKeyInfo
    extensions = []
    for tag, value in items[i:]:
        if tag == 0xA3:  # extensions [3] EXPLICIT
            extensions = _parse_extensions(value)
    return issuer, subject, extensions


def _oid_to_hex(oid):
    """DER content bytes (hex) of an OBJECT IDENTIFIER given in dotted form."""
    arcs = [int(part) for part in oid.split(".")]
    body = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            chunk.insert(0, (arc & 0x7F) | 0x80)
            arc >>= 7
        body.extend(chunk)
    return body.hex()


def _oid_hash(oids):
    if not oids:
        return _ZERO10
    return _sha12(",".join(_oid_to_hex(oid) for oid in oids))


def ja4x(cert_der):
    """Return the JA4X fingerprint for a DER-encoded X.509 certificate."""
    issuer, subject, extensions = _parse_certificate(cert_der)
    return "{}_{}_{}".format(
        _oid_hash(issuer), _oid_hash(subject), _oid_hash(extensions)
    )


# ---------------------------------------------------------------------------
# JA4T -- TCP SYN fingerprint
# ---------------------------------------------------------------------------

def ja4t(syn):
    """Return the JA4T fingerprint for a TCP SYN packet dict."""
    window = syn.get("window")
    options = syn.get("options") or []
    mss = syn.get("mss")
    scale = syn.get("window_scale")
    return "{}_{}_{}_{}".format(
        window if window is not None else 0,
        "-".join(str(option) for option in options),
        mss if mss is not None else 0,
        scale if scale is not None else 0,
    )


# ---------------------------------------------------------------------------
# JA4H -- HTTP request fingerprint
# ---------------------------------------------------------------------------

def _method_code(method):
    text = (method or "").upper()
    return _HTTP_METHOD.get(text, text[:2].lower())


def _http_version_code(version):
    text = str(version or "")
    if text.upper().startswith("HTTP/"):
        text = text[5:]
    text = text.replace(".", "")
    if len(text) >= 2:
        return text[:2]
    return (text + "0") if text else "11"


def _language_code(language):
    if not language:
        return "0000"
    primary = language.replace("-", "").replace(";", ",").lower().split(",")[0]
    primary = primary[:4]
    return primary + "0" * (4 - len(primary))


def _cookie_pairs(cookie):
    if not cookie:
        return []
    if isinstance(cookie, (list, tuple)):
        raw = [str(item) for item in cookie]
    else:
        raw = str(cookie).split(";")
    pairs = []
    for item in raw:
        item = item.strip()
        if not item:
            continue
        pairs.append((item.split("=", 1)[0].strip(), item))
    return pairs


def ja4h(req):
    """Return the JA4H fingerprint for a parsed HTTP request dict."""
    headers = req.get("headers") or []
    names = []
    for header in headers:
        if isinstance(header, (list, tuple)):
            name = header[0] if header else ""
        else:
            name = str(header).split(":", 1)[0]
        names.append(name)

    lowered = [name.lower() for name in names]
    has_cookie = req.get("cookie") is not None or "cookie" in lowered
    has_referer = req.get("referer") is not None or "referer" in lowered

    kept = [
        name for name in names
        if not name.startswith(":")
        and name.lower() not in ("cookie", "referer")
    ]

    if headers:
        count = len(kept)
    else:
        count = req.get("header_count") or 0
    count = "99" if count > 99 else "{:02d}".format(count)

    pairs = _cookie_pairs(req.get("cookie"))
    if pairs:
        pairs.sort(key=lambda pair: pair[0])
        cookie_names = _sha12(",".join(pair[0] for pair in pairs))
        cookie_values = _sha12(",".join(pair[1] for pair in pairs))
    else:
        cookie_names = _ZERO12
        cookie_values = _ZERO12

    a = "{}{}{}{}{}{}".format(
        _method_code(req.get("method")),
        _http_version_code(req.get("version")),
        "c" if has_cookie else "n",
        "r" if has_referer else "n",
        count,
        _language_code(req.get("language")),
    )
    b = _sha12(",".join(kept))
    return "{}_{}_{}_{}".format(a, b, cookie_names, cookie_values)
