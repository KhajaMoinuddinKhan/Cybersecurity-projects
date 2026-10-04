"""Synthetic pcap / pcapng fixture builder (pure standard library).

Builds byte-exact captures that exercise ``src/pcap.py`` and ``src/tls.py``.
Nothing here uses scapy or dpkt: pcap headers, Ethernet/IP/TCP/UDP framing,
TLS records and a small DER certificate are all written by hand with ``struct``.

The component builders (``build_client_hello_record`` and friends) are exposed
so tests can assert parsed values against exactly what was emitted.
"""

import hashlib
import os
import socket
import struct
import tempfile

# ---------------------------------------------------------------------------
# expected TLS / HTTP field values
# ---------------------------------------------------------------------------

CLIENT_HELLO_SNI = "example.com"
CLIENT_HELLO_ALPN = [b"h2", b"http/1.1"]
CLIENT_HELLO_CIPHERS = [0x0A0A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xCCA8, 0xCCA9]
CLIENT_HELLO_EXTENSIONS = [0x1A1A, 0x0000, 0x000B, 0x000A, 0x000D, 0x0010, 0x002B, 0x002D, 0x0033]
CLIENT_HELLO_CURVES = [0x2A2A, 0x001D, 0x0017, 0x0018]
CLIENT_HELLO_POINT_FORMATS = [0x00]
CLIENT_HELLO_SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
CLIENT_HELLO_VERSIONS = [0x0304, 0x0303]
CLIENT_HELLO_GREASE = [0x0A0A, 0x1A1A, 0x2A2A]
CLIENT_HELLO_SESSION_ID = bytes(range(32, 48))

SERVER_HELLO_CIPHER = 0x1301
SERVER_HELLO_ALPN = b"h2"
SERVER_HELLO_EXTENSIONS = [0x002B, 0x0010, 0x0033]

HTTP_REQUEST_LINES = [
    "GET /index.html HTTP/1.1",
    "Host: example.com",
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Accept: text/html,application/xhtml+xml",
    "Accept-Language: en-US,en;q=0.9",
    "Referer: https://example.com/",
    "Cookie: session=abc123; theme=dark",
    "Accept-Encoding: gzip, deflate",
    "Connection: keep-alive",
]
HTTP_METHOD = "GET"
HTTP_VERSION = "HTTP/1.1"
HTTP_COOKIE = "session=abc123; theme=dark"
HTTP_REFERER = "https://example.com/"
HTTP_LANGUAGE = "en-US,en;q=0.9"
HTTP_HEADER_COUNT = 6  # Host, UA, Accept, Accept-Language, Accept-Encoding, Connection

TCP_SYN_WINDOW = 64240
TCP_SYN_OPTIONS_KINDS = [2, 4, 8, 1, 3]
TCP_SYN_MSS = 1460
TCP_SYN_WINDOW_SCALE = 7

IPV4_CLIENT = "192.0.2.10"
IPV4_SERVER = "198.51.100.20"
IPV6_CLIENT = "2001:db8::10"
IPV6_SERVER = "2001:db8::20"
TLS_CLIENT_PORT = 49152
TLS_SERVER_PORT = 443
HTTP_CLIENT_PORT = 49153
HTTP_SERVER_PORT = 80
DNS_CLIENT_PORT = 5353
DNS_SERVER_PORT = 53
DNS_PAYLOAD = b"\x12\x34\x01\x00\x00\x01"
VLAN_ID = 100


def _u8(n):
    return struct.pack(">B", n)


def _u16(n):
    return struct.pack(">H", n)


def _u24(n):
    return struct.pack(">I", n)[1:]


def _u32(n):
    return struct.pack(">I", n)


def _ext(etype, data):
    return _u16(etype) + _u16(len(data)) + data


# ---------------------------------------------------------------------------
# TLS component builders
# ---------------------------------------------------------------------------

def _build_client_hello_extensions():
    exts = b""
    exts += _ext(0x1A1A, b"")                                       # GREASE
    host = CLIENT_HELLO_SNI.encode("ascii")
    sni = _u8(0) + _u16(len(host)) + host
    exts += _ext(0x0000, _u16(len(sni)) + sni)                      # server_name
    pf = bytes(CLIENT_HELLO_POINT_FORMATS)
    exts += _ext(0x000B, _u8(len(pf)) + pf)                         # ec_point_formats
    grp = b"".join(_u16(g) for g in CLIENT_HELLO_CURVES)
    exts += _ext(0x000A, _u16(len(grp)) + grp)                      # supported_groups
    sa = b"".join(_u16(s) for s in CLIENT_HELLO_SIG_ALGS)
    exts += _ext(0x000D, _u16(len(sa)) + sa)                        # signature_algorithms
    alpn = b"".join(_u8(len(p)) + p for p in CLIENT_HELLO_ALPN)
    exts += _ext(0x0010, _u16(len(alpn)) + alpn)                    # ALPN
    sv = b"".join(_u16(v) for v in CLIENT_HELLO_VERSIONS)
    exts += _ext(0x002B, _u8(len(sv)) + sv)                         # supported_versions
    exts += _ext(0x002D, _u8(1) + _u8(1))                           # psk_key_exchange_modes
    exts += _ext(0x0033, _u16(0))                                   # key_share
    return exts


def build_client_hello_body():
    random = bytes(range(32))
    session_id = CLIENT_HELLO_SESSION_ID
    ciphers = b"".join(_u16(c) for c in CLIENT_HELLO_CIPHERS)
    exts = _build_client_hello_extensions()
    return (_u16(0x0303) + random + _u8(len(session_id)) + session_id
            + _u16(len(ciphers)) + ciphers + _u8(1) + _u8(0)
            + _u16(len(exts)) + exts)


def build_client_hello_record():
    body = build_client_hello_body()
    hs = _u8(1) + _u24(len(body)) + body
    return _u8(22) + _u16(0x0301) + _u16(len(hs)) + hs


def build_server_hello_body():
    random = bytes(range(32, 64))
    session_id = CLIENT_HELLO_SESSION_ID
    exts = b""
    exts += _ext(0x002B, _u16(0x0304))                              # supported_versions
    alpn_data = _u16(3) + _u8(len(SERVER_HELLO_ALPN)) + SERVER_HELLO_ALPN
    exts += _ext(0x0010, alpn_data)                                 # ALPN
    exts += _ext(0x0033, _u16(2) + _u16(0x001D) + _u16(32) + bytes(32))  # key_share
    return (_u16(0x0303) + random + _u8(len(session_id)) + session_id
            + _u16(SERVER_HELLO_CIPHER) + _u8(0) + _u16(len(exts)) + exts)


def build_server_hello_record():
    body = build_server_hello_body()
    hs = _u8(2) + _u24(len(body)) + body
    return _u8(22) + _u16(0x0303) + _u16(len(hs)) + hs


def build_der_certificate():
    oid_rsa = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
    oid_sha256_rsa = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B])
    oid_cn = bytes([0x55, 0x04, 0x03])

    def der(tag, content):
        length = len(content)
        if length < 0x80:
            lenb = bytes([length])
        elif length < 0x100:
            lenb = bytes([0x81, length])
        else:
            lenb = bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        return bytes([tag]) + lenb + content

    alg = der(0x30, der(0x06, oid_sha256_rsa) + der(0x05, b""))
    rsa_alg = der(0x30, der(0x06, oid_rsa) + der(0x05, b""))
    name = der(0x30, der(0x31, der(0x30, der(0x06, oid_cn)
                                     + der(0x0C, b"example.com"))))
    validity = der(0x30, der(0x17, b"240101000000Z")
                   + der(0x17, b"340101000000Z"))
    spki = der(0x30, rsa_alg + der(0x03, b"\x00" + bytes(64)))
    tbs = der(0x30, der(0xA0, der(0x02, b"\x02")) + der(0x02, b"\x01")
              + alg + name + validity + name + spki)
    return der(0x30, tbs + alg + der(0x03, b"\x00" + bytes(64)))


def build_certificate_message_body(tls13=True):
    der_cert = build_der_certificate()
    if tls13:
        entries = _u24(len(der_cert)) + der_cert + _u16(0)
        return _u8(0) + _u24(len(entries)) + entries
    entries = _u24(len(der_cert)) + der_cert
    return _u24(len(entries)) + entries


def build_certificate_record(tls13=True):
    body = build_certificate_message_body(tls13=tls13)
    hs = _u8(11) + _u24(len(body)) + body
    return _u8(22) + _u16(0x0303) + _u16(len(hs)) + hs


def build_http_get():
    return ("\r\n".join(HTTP_REQUEST_LINES) + "\r\n\r\n").encode("ascii")


def build_tcp_syn_options():
    opts = b""
    opts += bytes([2, 4]) + _u16(TCP_SYN_MSS)      # MSS
    opts += bytes([4, 2])                          # SACK permitted
    opts += bytes([8, 10]) + bytes(8)              # timestamps
    opts += bytes([1])                             # NOP
    opts += bytes([3, 3, TCP_SYN_WINDOW_SCALE])    # window scale
    return opts


# ---------------------------------------------------------------------------
# packet framing
# ---------------------------------------------------------------------------

def _tcp(sport, dport, seq, ack, flags, window=65535, options=b"", payload=b""):
    if len(options) % 4:
        options = options + b"\x00" * (4 - len(options) % 4)
    data_off = 5 + len(options) // 4
    hdr = (_u16(sport) + _u16(dport) + _u32(seq) + _u32(ack)
           + bytes([(data_off << 4) & 0xF0, flags]) + _u16(window)
           + _u16(0) + _u16(0) + options)
    return hdr + payload


def _udp(sport, dport, payload):
    return _u16(sport) + _u16(dport) + _u16(8 + len(payload)) + _u16(0) + payload


def _ip4(s):
    return bytes(int(x) for x in s.split("."))


def _ipv4_header(src, dst, proto, payload, ttl=64, ident=0):
    total = 20 + len(payload)
    hdr = (bytes([(4 << 4) | 5, 0]) + _u16(total) + _u16(ident) + _u16(0x4000)
           + bytes([ttl, proto]) + _u16(0) + _ip4(src) + _ip4(dst))
    return hdr + payload


def _ipv6_header(src, dst, nh, payload, hop=64):
    hdr = struct.pack(">IHBB", 0x60000000, len(payload), nh, hop)
    hdr += socket.inet_pton(socket.AF_INET6, src)
    hdr += socket.inet_pton(socket.AF_INET6, dst)
    return hdr + payload


def _eth(payload, ethertype, vlan=None):
    dst = b"\x02\x00\x00\x00\x00\x01"
    src = b"\x02\x00\x00\x00\x00\x02"
    if vlan is not None:
        hdr = dst + src + _u16(0x8100) + _u16(vlan) + _u16(ethertype)
    else:
        hdr = dst + src + _u16(ethertype)
    return hdr + payload


def _frame(ip_version, src, dst, proto, segment, vlan=None):
    if ip_version == 6:
        ip = _ipv6_header(src, dst, proto, segment)
        return _eth(ip, 0x86DD, vlan=vlan)
    ip = _ipv4_header(src, dst, proto, segment)
    return _eth(ip, 0x0800, vlan=vlan)


def build_frames(ip_version=4, vlan=None):
    client = IPV6_CLIENT if ip_version == 6 else IPV4_CLIENT
    server = IPV6_SERVER if ip_version == 6 else IPV4_SERVER
    ch = build_client_hello_record()
    sh = build_server_hello_record()
    cert = build_certificate_record()
    http = build_http_get()
    syn = build_tcp_syn_options()

    frames = []
    # TLS handshake + data
    frames.append(_frame(ip_version, client, server, 6,
                         _tcp(TLS_CLIENT_PORT, TLS_SERVER_PORT, 1000, 0, 0x02,
                              TCP_SYN_WINDOW, syn), vlan))
    frames.append(_frame(ip_version, server, client, 6,
                         _tcp(TLS_SERVER_PORT, TLS_CLIENT_PORT, 5000, 1001, 0x12,
                              65535, syn), vlan))
    frames.append(_frame(ip_version, client, server, 6,
                         _tcp(TLS_CLIENT_PORT, TLS_SERVER_PORT, 1001, 5001, 0x10,
                              TCP_SYN_WINDOW, b""), vlan))
    frames.append(_frame(ip_version, client, server, 6,
                         _tcp(TLS_CLIENT_PORT, TLS_SERVER_PORT, 1001, 5001, 0x18,
                              TCP_SYN_WINDOW, b"", ch), vlan))
    frames.append(_frame(ip_version, server, client, 6,
                         _tcp(TLS_SERVER_PORT, TLS_CLIENT_PORT, 5001, 1001 + len(ch),
                              0x10, 65535, b""), vlan))
    frames.append(_frame(ip_version, server, client, 6,
                         _tcp(TLS_SERVER_PORT, TLS_CLIENT_PORT, 5001, 1001 + len(ch),
                              0x18, 65535, b"", sh), vlan))
    frames.append(_frame(ip_version, server, client, 6,
                         _tcp(TLS_SERVER_PORT, TLS_CLIENT_PORT, 5001 + len(sh),
                              1001 + len(ch), 0x18, 65535, b"", cert), vlan))
    # HTTP connection
    frames.append(_frame(ip_version, client, server, 6,
                         _tcp(HTTP_CLIENT_PORT, HTTP_SERVER_PORT, 7000, 0, 0x02,
                              TCP_SYN_WINDOW, syn), vlan))
    frames.append(_frame(ip_version, server, client, 6,
                         _tcp(HTTP_SERVER_PORT, HTTP_CLIENT_PORT, 9000, 7001, 0x12,
                              65535, syn), vlan))
    frames.append(_frame(ip_version, client, server, 6,
                         _tcp(HTTP_CLIENT_PORT, HTTP_SERVER_PORT, 7001, 9001, 0x18,
                              TCP_SYN_WINDOW, b"", http), vlan))
    # UDP query
    frames.append(_frame(ip_version, client, server, 17,
                         _udp(DNS_CLIENT_PORT, DNS_SERVER_PORT, DNS_PAYLOAD), vlan))
    return frames


# ---------------------------------------------------------------------------
# file writers
# ---------------------------------------------------------------------------

def _classic_bytes(frames, linktype=1):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    ts = 1700000000.0
    for frame in frames:
        ts += 0.001
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec += 1
            usec -= 1_000_000
        out += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
    return out


def _pcapng_block(btype, body):
    pad = (-len(body)) % 4
    body = body + b"\x00" * pad
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def _pcapng_bytes(frames, linktype=1):
    out = b""
    out += _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = struct.pack("<HHI", linktype, 0, 65535)
    idb += struct.pack("<HH", 9, 1) + bytes([6]) + b"\x00\x00\x00"  # if_tsresol
    idb += struct.pack("<HH", 0, 0)                                 # opt_endofopt
    out += _pcapng_block(1, idb)
    ts = 1700000000.0
    for frame in frames:
        ts += 0.001
        us = int(round(ts * 1_000_000))
        body = struct.pack("<IIIII", 0, (us >> 32) & 0xFFFFFFFF,
                           us & 0xFFFFFFFF, len(frame), len(frame)) + frame
        out += _pcapng_block(6, body)
    return out


def _default_dir():
    path = os.path.join(tempfile.gettempdir(), "tls_fp_fixtures")
    os.makedirs(path, exist_ok=True)
    return path


def _write(path, data, suffix=".pcap"):
    if path is None:
        name = hashlib.md5(data).hexdigest()[:12] + suffix
        path = os.path.join(_default_dir(), name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def make_classic_pcap(path=None, ip_version=4, vlan=None):
    return _write(path, _classic_bytes(build_frames(ip_version, vlan), 1))


def make_ipv6_pcap(path=None):
    return make_classic_pcap(path, ip_version=6)


def make_vlan_pcap(path=None):
    return make_classic_pcap(path, vlan=VLAN_ID)


def make_pcapng(path=None, ip_version=4):
    return _write(path, _pcapng_bytes(build_frames(ip_version), 1), suffix=".pcapng")


def make_truncated_pcap(path=None):
    data = _classic_bytes(build_frames(4), 1)
    return _write(path, data[:-7])


def make_bad_magic_pcap(path=None):
    return _write(path, b"\xde\xad\xbe\xef" + bytes(64))
