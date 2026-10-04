"""TLS / TCP / HTTP parsers that operate on raw byte streams.

The functions here do not care about packet framing: they take the bytes of a
TLS record stream (or a single handshake body) and pull out the fields the
fingerprinting modules (ja3 / ja4) need.

Ordering matters: cipher suites, extensions, curves, point formats, signature
algorithms and supported versions are returned in WIRE ORDER and GREASE values
are kept in the lists.  The fingerprint modules strip grease themselves; the
values that were stripped are also reported separately in ``grease``.
"""

import re
import struct

# ---------------------------------------------------------------------------
# Encrypted Client Hello (ECH)
# ---------------------------------------------------------------------------
# ECH is offered by the client in TLS extension 0xfe0d.  When the offer is
# honoured, the outer ClientHello a passive observer sees carries a public name
# (a decoy) instead of the real SNI, and the real extension set is sealed inside
# an encrypted inner ClientHello.  A JA3/JA4 computed from such a hello then
# describes only the deliberately generic outer shell, so it is NOT a reliable
# client identifier.
#
# The extension is an offer, not a proof.  Chrome offers ECH to every host it
# talks to -- including hosts that publish no ECHConfig at all -- and it shapes
# the offer exactly like a real one, with a well-formed outer structure and
# random ``config_id`` and ``enc``/``payload`` bytes, so a passive reader cannot
# tell a real offer from GREASE.  This module therefore reports what was seen
# (an offer, its shape, the config ids it could read) and never asserts that the
# SNI beside it is a decoy.
ECH_EXTENSION = 0xfe0d

# ---------------------------------------------------------------------------
# TLS records
# ---------------------------------------------------------------------------

def iter_tls_records(payload):
    """Split a TLS record stream into ``{record_type, version, body}`` dicts.

    Truncated trailing data (fewer bytes than a full record) is tolerated by
    stopping early instead of raising.
    """
    records = []
    i = 0
    n = len(payload)
    while i + 5 <= n:
        record_type = payload[i]
        version = struct.unpack_from(">H", payload, i + 1)[0]
        length = struct.unpack_from(">H", payload, i + 3)[0]
        if i + 5 + length > n:
            break
        records.append({
            "record_type": record_type,
            "version": version,
            "body": bytes(payload[i + 5:i + 5 + length]),
        })
        i += 5 + length
    return records


# ---------------------------------------------------------------------------
# ClientHello
# ---------------------------------------------------------------------------

def parse_client_hello(body):
    """Parse a ClientHello.

    ``body`` may be either the full handshake message (type + 3-byte length +
    ClientHello) or the bare ClientHello body; the handshake header is stripped
    automatically when present.
    """
    body = _strip_handshake(body, 1)
    p = 0
    n = len(body)
    version = _need_u16(body, p)
    p += 2
    p += 32  # random
    sid_len = _need_u8(body, p)
    p += 1
    session_id = bytes(body[p:p + sid_len])
    p += sid_len
    cs_len = _need_u16(body, p)
    p += 2
    ciphers = []
    cs_end = min(n, p + cs_len)
    while p + 2 <= cs_end:
        ciphers.append(_need_u16(body, p))
        p += 2
    p = cs_end
    comp_len = _need_u8(body, p)
    p += 1
    p += comp_len

    extensions = []
    sni = None
    alpn = []
    curves = []
    point_formats = []
    sig_algs = []
    supported_versions = []
    ech_ext_data = None

    if p + 2 <= n:
        ext_total = _need_u16(body, p)
        p += 2
        ext_end = min(n, p + ext_total)
        while p + 4 <= ext_end:
            etype = _need_u16(body, p)
            elen = _need_u16(body, p + 2)
            p += 4
            edata = body[p:p + elen]
            p += elen
            extensions.append(etype)
            if etype == 0x0000:
                sni = _parse_sni(edata) or sni
            elif etype == 0x0010:
                alpn = _parse_alpn(edata)
            elif etype == 0x000A:
                curves = _parse_u16_list(edata, 2)
            elif etype == 0x000B:
                if edata:
                    point_formats = list(edata[1:1 + edata[0]])
            elif etype == 0x000D:
                sig_algs = _parse_u16_list(edata, 2)
            elif etype == 0x002B:
                supported_versions = _parse_u16_list(edata, 1)
            elif etype == ECH_EXTENSION:
                ech_ext_data = bytes(edata)

    # ECH awareness: never changes existing keys; a malformed body still
    # reports ech=True and simply leaves the parsed fields empty.
    ech = ech_ext_data is not None
    ech_outer = False
    ech_config_ids = []
    if ech:
        ech_outer, ech_config_ids = _parse_ech(ech_ext_data)

    grease = []
    for seq in (ciphers, extensions, curves, point_formats, sig_algs,
                supported_versions):
        for value in seq:
            if _is_grease(value):
                grease.append(value)

    return {
        "version": version,
        "session_id": session_id,
        "ciphers": ciphers,
        "extensions": extensions,
        "sni": sni,
        "alpn": alpn,
        "curves": curves,
        "point_formats": point_formats,
        "sig_algs": sig_algs,
        "supported_versions": supported_versions,
        "grease": grease,
        "ech": ech,
        "ech_outer": ech_outer,
        "ech_config_ids": ech_config_ids,
    }


def is_ech(hello):
    """True when *hello* (a :func:`parse_client_hello` result) offered ECH."""
    if not isinstance(hello, dict):
        return False
    extensions = hello.get("extensions")
    if not isinstance(extensions, (list, tuple)):
        return False
    return ECH_EXTENSION in extensions


def fingerprint_caveat(hello):
    """Return a one-sentence caveat for an ECH hello, or None otherwise.

    The extension says the client offered ECH; it does not say the offer was
    honoured, because a GREASE offer is shaped exactly like a real one and only
    the destination's ECHConfig would tell them apart.  If it was honoured, the
    fingerprint describes the *outer* hello, whose extension set is deliberately
    generic and may be padded or randomised, and the SNI it carries is a public
    name rather than the site actually visited.
    """
    if not is_ech(hello):
        return None
    return ("this ClientHello offered ECH (or an ECH GREASE shaped exactly like "
            "one); if the offer was honoured the fingerprint describes the outer "
            "ClientHello, whose extension set is deliberately generic, so it is "
            "not a reliable client identifier.")


# ---------------------------------------------------------------------------
# ServerHello
# ---------------------------------------------------------------------------

def parse_server_hello(body):
    """Parse a ServerHello; returns version, chosen cipher, extensions, ALPN."""
    body = _strip_handshake(body, 2)
    p = 0
    n = len(body)
    version = _need_u16(body, p)
    p += 2
    p += 32  # random
    sid_len = _need_u8(body, p)
    p += 1
    p += sid_len
    cipher = _need_u16(body, p)
    p += 2
    comp_len = _need_u8(body, p)
    p += 1
    p += comp_len

    extensions = []
    alpn = None
    if p + 2 <= n:
        ext_total = _need_u16(body, p)
        p += 2
        ext_end = min(n, p + ext_total)
        while p + 4 <= ext_end:
            etype = _need_u16(body, p)
            elen = _need_u16(body, p + 2)
            p += 4
            edata = body[p:p + elen]
            p += elen
            extensions.append(etype)
            if etype == 0x0010:
                protocols = _parse_alpn(edata)
                if protocols:
                    alpn = protocols[0]
    return {
        "version": version,
        "cipher": cipher,
        "extensions": extensions,
        "alpn": alpn,
    }


# ---------------------------------------------------------------------------
# Certificate message
# ---------------------------------------------------------------------------

def parse_certificate_message(body):
    """Return the DER-encoded certificates from a TLS Certificate message.

    Handles both layouts:

    * TLS 1.2: 3-byte list length, then 3-byte length per certificate
    * TLS 1.3: 1-byte request context length (+ context), 3-byte list length,
      then 3-byte length per certificate + 2-byte extensions length per entry
    """
    body = _strip_handshake(body, 11)
    certs = _parse_cert_list_tls13(body)
    if certs is not None:
        return certs
    certs = _parse_cert_list_tls12(body)
    if certs is not None:
        return certs
    raise ValueError("malformed TLS certificate message")


def _parse_cert_list_tls13(body):
    if len(body) < 4:
        return None
    ctx_len = body[0]
    if 1 + ctx_len + 3 > len(body):
        return None
    p = 1 + ctx_len
    total = int.from_bytes(body[p:p + 3], "big")
    p += 3
    if p + total > len(body):
        return None
    end = p + total
    certs = []
    while p + 3 <= end:
        clen = int.from_bytes(body[p:p + 3], "big")
        p += 3
        if clen <= 0 or p + clen > end:
            return None
        der = bytes(body[p:p + clen])
        p += clen
        if der[0] != 0x30:
            return None
        if p + 2 > end:
            return None
        ext_len = int.from_bytes(body[p:p + 2], "big")
        p += 2
        if p + ext_len > end:
            return None
        p += ext_len
        certs.append(der)
    if p != end or not certs:
        return None
    return certs


def _parse_cert_list_tls12(body):
    if len(body) < 3:
        return None
    total = int.from_bytes(body[0:3], "big")
    p = 3
    if p + total > len(body):
        return None
    end = p + total
    certs = []
    while p + 3 <= end:
        clen = int.from_bytes(body[p:p + 3], "big")
        p += 3
        if clen <= 0 or p + clen > end:
            return None
        der = bytes(body[p:p + clen])
        p += clen
        if der[0] != 0x30:
            return None
        certs.append(der)
    if p != end or not certs:
        return None
    return certs


# ---------------------------------------------------------------------------
# TCP SYN / HTTP
# ---------------------------------------------------------------------------

def parse_tcp_syn(packet):
    """Extract the SYN-relevant fields from a packet dict."""
    return {
        "window": packet.get("window", 0),
        "options": list(packet.get("tcp_options") or []),
        "mss": packet.get("mss"),
        "window_scale": packet.get("window_scale"),
    }


HTTP_METHODS = frozenset((
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
))
HTTP_VERSION_RE = re.compile(r"^HTTP/\d\.\d$")


def parse_http_request(payload):
    """Parse an HTTP/1.x request line and headers.

    ``header_count`` excludes the Cookie and Referer headers.
    """
    if isinstance(payload, (bytes, bytearray)):
        text = bytes(payload).decode("latin-1")
    else:
        text = payload
    head = text.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    if not lines or not lines[0].strip():
        raise ValueError("empty HTTP request")

    # A request line is exactly "METHOD SP request-target SP HTTP/x.y".  Without
    # this check any byte stream parses as a request: a TLS record begins
    # 0x16 0x03, which was silently accepted and produced a fingerprint built
    # from a record header rather than from a request.
    parts = lines[0].split(" ")
    if len(parts) != 3:
        raise ValueError("not an HTTP request line: %r" % lines[0][:48])
    method, _target, version = parts
    if method not in HTTP_METHODS:
        raise ValueError("unknown HTTP method %r" % method)
    if not HTTP_VERSION_RE.match(version):
        raise ValueError("not an HTTP version: %r" % version)

    headers = []
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if sep:
            headers.append((name.strip(), value.strip()))
        else:
            headers.append((line.strip(), ""))

    cookie = None
    referer = None
    language = None
    header_count = 0
    for name, value in headers:
        lname = name.lower()
        if lname == "cookie":
            cookie = value
        elif lname == "referer":
            referer = value
        elif lname == "accept-language":
            language = value
        if lname not in ("cookie", "referer"):
            header_count += 1

    return {
        "method": method,
        "version": version,
        "headers": headers,
        "cookie": cookie,
        "referer": referer,
        "language": language,
        "header_count": header_count,
    }


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _strip_handshake(body, msg_type):
    if len(body) >= 4 and body[0] == msg_type:
        length = int.from_bytes(body[1:4], "big")
        if length == len(body) - 4:
            return body[4:]
    return body


def _need_u8(body, p):
    if p + 1 > len(body):
        raise ValueError("truncated TLS structure")
    return body[p]


def _need_u16(body, p):
    if p + 2 > len(body):
        raise ValueError("truncated TLS structure")
    return struct.unpack_from(">H", body, p)[0]


def _is_grease(value):
    return (value >> 8) == (value & 0xFF) and (value & 0x0F) == 0x0A


def _parse_ech(edata):
    """Best-effort parse of an ECH (0xfe0d) extension body.

    The body is an ``ECHClientHello``: a one-byte type; for the ``outer`` type
    it is followed by a cipher suite, a one-byte ``config_id`` and
    length-prefixed ``enc`` / ``payload`` fields.  Returns
    ``(outer_parsed, config_ids)``.  A malformed body yields ``(False, [])``
    and never raises.
    """
    try:
        if not edata:
            return False, []
        ech_type = edata[0]
        if ech_type == 1:  # inner: no plaintext fields to read
            return True, []
        if ech_type != 0:  # unknown type
            return False, []
        # type(1) + kdf_id(2) + aead_id(2) + config_id(1)
        if len(edata) < 6:
            return False, []
        return True, [edata[5]]
    except Exception:
        return False, []


def _parse_sni(edata):
    if len(edata) < 2:
        return None
    list_len = struct.unpack_from(">H", edata, 0)[0]
    p = 2
    end = min(len(edata), 2 + list_len)
    while p + 3 <= end:
        name_type = edata[p]
        name_len = struct.unpack_from(">H", edata, p + 1)[0]
        p += 3
        name = edata[p:p + name_len]
        p += name_len
        if name_type == 0:
            return bytes(name).decode("utf-8", "replace")
    return None


def _parse_alpn(edata):
    out = []
    if len(edata) < 2:
        return out
    list_len = struct.unpack_from(">H", edata, 0)[0]
    p = 2
    end = min(len(edata), 2 + list_len)
    while p < end:
        plen = edata[p]
        p += 1
        out.append(bytes(edata[p:p + plen]))
        p += plen
    return out


def _parse_u16_list(edata, length_size):
    out = []
    if len(edata) < length_size:
        return out
    if length_size == 1:
        total = edata[0]
        p = 1
    else:
        total = struct.unpack_from(">H", edata, 0)[0]
        p = 2
    end = min(len(edata), p + total)
    while p + 2 <= end:
        out.append(struct.unpack_from(">H", edata, p)[0])
        p += 2
    return out
