"""QUIC (HTTP/3) Initial-packet parsing and RFC 9001 decryption.

The console's capture filter is TCP-only, so every QUIC / HTTP-3 handshake is
invisible.  QUIC Initial packets are encrypted, but their keys are derived from
a publicly-known salt and the client's destination connection ID (RFC 9001
section 5.2), so a passive observer can derive them and read the ClientHello.

This module implements the parts of RFC 9001 that make that possible:

* QUIC variable-length integers and long/short header framing
* Initial-secret derivation (SHA-256 HKDF, TLS 1.3 style HKDF-Expand-Label)
* header protection removal and AEAD payload decryption (AES-ECB + AES-128-GCM)
* CRYPTO-frame extraction and reassembly, and ClientHello recovery

AES lives in the third-party ``cryptography`` package, imported guarded.  When
it is missing the module still parses headers and reports the version and
connection IDs, and says plainly that it cannot decrypt -- it never pretends.
"""

from __future__ import annotations

import hmac
from hashlib import sha256

try:  # pragma: no cover - the no-crypto path is exercised by monkeypatching
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    HAVE_CRYPTO = False

__all__ = [
    "HAVE_CRYPTO", "QUIC_V1", "QUIC_V2", "INITIAL_SALT_V1", "INITIAL_SALT_V2",
    "QuicUnavailable", "read_varint", "parse_packets", "derive_initial_keys",
    "decrypt_initial", "crypto_frames", "extract_client_hello",
    "client_hello_from_datagram",
]

QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF

INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
INITIAL_SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")

_SALT_BY_VERSION = {QUIC_V1: INITIAL_SALT_V1, QUIC_V2: INITIAL_SALT_V2}

# Long-header packet types.  QUIC v2 (RFC 9369) renumbers them.
_LONG_TYPES_V1 = {0: "initial", 1: "0-rtt", 2: "handshake", 3: "retry"}
_LONG_TYPES_V2 = {0: "retry", 1: "initial", 2: "0-rtt", 3: "handshake"}

_PADDING_FRAME = 0x00
_PING_FRAME = 0x01
_CRYPTO_FRAME = 0x06


class QuicUnavailable(Exception):
    """Raised when QUIC decryption is attempted without the crypto library."""


# ---------------------------------------------------------------------------
# QUIC variable-length integers
# ---------------------------------------------------------------------------

def read_varint(data, offset):
    """Decode the QUIC variable-length integer at ``offset``.

    Returns ``(value, width)`` where ``width`` is the encoded length in bytes
    (1, 2, 4 or 8), or ``None`` when fewer bytes than the width are present.
    """
    if offset < 0 or offset >= len(data):
        return None
    first = data[offset]
    width = 1 << (first >> 6)  # top two bits: 0->1, 1->2, 2->4, 3->8
    if offset + width > len(data):
        return None
    value = first & 0x3F
    for i in range(1, width):
        value = (value << 8) | data[offset + i]
    return value, width


# ---------------------------------------------------------------------------
# Packet framing
# ---------------------------------------------------------------------------

def _packet_type(first_byte, version):
    table = _LONG_TYPES_V2 if version == QUIC_V2 else _LONG_TYPES_V1
    return table.get((first_byte & 0x30) >> 4, "unknown")


def _header(long_header, packet_type, version, dcid, scid, pn_offset,
            payload_offset, payload_length, raw):
    return {
        "long_header": long_header,
        "packet_type": packet_type,
        "version": version,
        "dcid": dcid,
        "scid": scid,
        "pn_offset": pn_offset,
        "payload_offset": payload_offset,
        "payload_length": payload_length,
        "raw": bytes(raw),
    }


def parse_packets(datagram):
    """Split a UDP datagram into its QUIC packets (header fields only).

    A datagram may carry several QUIC packets back to back; they are parsed in
    a loop.  Each returned dict has:

        long_header     bool
        packet_type     'initial' / '0-rtt' / 'handshake' / 'retry' /
                        'version-negotiation' / '1-rtt' / 'unknown'
        version         int (None for a short header)
        dcid, scid      bytes
        pn_offset       offset of the packet number within ``raw``, or None
        payload_offset  offset of the Length-delimited region (the packet
                        number); the AEAD ciphertext begins pn_length later
        payload_length  value of the Length field: packet number + AEAD payload
        raw             the packet's bytes

    Offsets are relative to the start of each packet's ``raw`` bytes.
    """
    packets = []
    data = bytes(datagram)
    offset = 0
    n = len(data)
    while offset < n:
        packet = _parse_one(data, offset)
        if packet is None:
            break
        packets.append(packet)
        step = len(packet["raw"])
        if step <= 0:
            break
        offset += step
    return packets


def _parse_one(data, offset):
    # Offsets in the returned dict are relative to the start of THIS packet
    # (i.e. index into ``raw``), so decrypt_initial works for any packet in a
    # multi-packet datagram.
    n = len(data)
    start = offset
    first = data[offset]
    if not first & 0x80:
        # Short header (1-RTT).  The destination connection ID length is not on
        # the wire (it is fixed by the connection), so the header cannot be
        # split further without context.
        return _header(False, "1-rtt", None, b"", b"", None,
                       1, n - offset - 1, data[offset:])

    if offset + 7 > n:
        return None
    version = int.from_bytes(data[offset + 1:offset + 5], "big")
    p = offset + 5
    dcid_len = data[p]
    p += 1
    if p + dcid_len > n:
        return None
    dcid = bytes(data[p:p + dcid_len])
    p += dcid_len
    if p >= n:
        return None
    scid_len = data[p]
    p += 1
    if p + scid_len > n:
        return None
    scid = bytes(data[p:p + scid_len])
    p += scid_len

    if version == 0:
        # Version Negotiation: no packet number and no Length field.
        return _header(True, "version-negotiation", 0, dcid, scid, None,
                       p - start, n - p, data[offset:])

    packet_type = _packet_type(first, version)

    if packet_type == "retry":
        # Retry: Retry Token then a 16-byte Retry Integrity Tag, no Length.
        return _header(True, "retry", version, dcid, scid, None,
                       p - start, n - p, data[offset:])

    if packet_type == "initial":
        token = read_varint(data, p)
        if token is None:
            return None
        token_len, token_width = token
        p += token_width
        if p + token_len > n:
            return None
        p += token_len

    length = read_varint(data, p)
    if length is None:
        return None
    payload_len, length_width = length
    pn_offset = p + length_width
    payload_end = pn_offset + payload_len
    if payload_end > n:
        payload_end = n
    return _header(True, packet_type, version, dcid, scid, pn_offset - start,
                   pn_offset - start, payload_len, data[offset:payload_end])


# ---------------------------------------------------------------------------
# HKDF / Initial secrets (RFC 9001 section 5.2)
# ---------------------------------------------------------------------------

def _hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, sha256).digest()


def _hkdf_expand(prk, info, length):
    out = bytearray()
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), sha256).digest()
        out += block
        counter += 1
    return bytes(out[:length])


def _hkdf_expand_label(secret, label, context, length):
    """TLS 1.3 style HKDF-Expand-Label (RFC 8446 section 7.1)."""
    full = b"tls13 " + label
    info = (length.to_bytes(2, "big") + bytes([len(full)]) + full +
            bytes([len(context)]) + context)
    return _hkdf_expand(secret, info, length)


def derive_initial_keys(dcid, version=QUIC_V1):
    """Derive the client Initial keys for ``dcid`` (RFC 9001 section 5.2)."""
    salt = _SALT_BY_VERSION.get(version)
    if salt is None:
        raise ValueError("no QUIC Initial salt for version 0x%08x" % (version,))
    initial_secret = _hkdf_extract(salt, bytes(dcid))
    client_initial_secret = _hkdf_expand_label(initial_secret, b"client in", b"", 32)
    return {
        "key": _hkdf_expand_label(client_initial_secret, b"quic key", b"", 16),
        "iv": _hkdf_expand_label(client_initial_secret, b"quic iv", b"", 12),
        "hp": _hkdf_expand_label(client_initial_secret, b"quic hp", b"", 16),
        "initial_secret": initial_secret,
        "client_initial_secret": client_initial_secret,
    }


# ---------------------------------------------------------------------------
# Header protection + AEAD (RFC 9001 sections 5.3 - 5.4)
# ---------------------------------------------------------------------------

def _aes_ecb_encrypt(key, data):
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _nonce(iv, packet_number):
    pad = packet_number.to_bytes(12, "big")
    return bytes(a ^ b for a, b in zip(iv, pad))


def decrypt_initial(packet, keys):
    """Remove header protection and decrypt one Initial packet.

    Returns ``{'plaintext': bytes, 'header': bytes, 'packet_number': int}``
    where ``header`` is the unprotected header used as the AEAD associated
    data.  Raises :class:`QuicUnavailable` without the crypto library and
    ``ValueError`` for a packet that cannot be decrypted.
    """
    if not HAVE_CRYPTO:
        raise QuicUnavailable(
            "QUIC Initial decryption needs the 'cryptography' package "
            "(pip install 'cryptography>=42'); the header was parsed but the "
            "payload cannot be decrypted"
        )
    raw = bytes(packet["raw"])
    pn_offset = packet.get("pn_offset")
    if pn_offset is None:
        raise ValueError("packet has no packet number field to decrypt")

    sample_offset = pn_offset + 4
    if sample_offset + 16 > len(raw):
        raise ValueError("truncated Initial: header-protection sample missing")
    sample = raw[sample_offset:sample_offset + 16]
    mask = _aes_ecb_encrypt(keys["hp"], sample)

    header = bytearray(raw)
    header[0] ^= mask[0] & 0x0F          # long header: low 4 bits protected
    pn_length = (header[0] & 0x03) + 1   # read AFTER unmasking the first byte
    if pn_offset + pn_length > len(raw):
        raise ValueError("truncated Initial: packet number field missing")
    for i in range(pn_length):
        header[pn_offset + i] ^= mask[1 + i]
    packet_number = int.from_bytes(header[pn_offset:pn_offset + pn_length], "big")

    payload_length = packet.get("payload_length")
    if payload_length is None:
        raise ValueError("packet has no Length field")
    payload_end = pn_offset + payload_length
    if payload_end > len(raw):
        raise ValueError("truncated Initial: payload shorter than Length field")
    ct_start = pn_offset + pn_length
    if payload_end - 16 < ct_start:
        raise ValueError("truncated Initial: payload too short for AEAD tag")
    ciphertext = bytes(raw[ct_start:payload_end - 16])
    tag = bytes(raw[payload_end - 16:payload_end])
    aad = bytes(header[:ct_start])
    nonce = _nonce(keys["iv"], packet_number)
    plaintext = AESGCM(keys["key"]).decrypt(nonce, ciphertext + tag, aad)
    return {"plaintext": plaintext, "header": aad, "packet_number": packet_number}


# ---------------------------------------------------------------------------
# CRYPTO frames and ClientHello recovery
# ---------------------------------------------------------------------------

def crypto_frames(plaintext):
    """Return the CRYPTO frames in a decrypted payload.

    Each frame is ``{'offset': int, 'data': bytes}``.  PADDING is skipped and
    parsing stops cleanly at the first frame it does not understand.
    """
    frames = []
    data = bytes(plaintext)
    p = 0
    n = len(data)
    while p < n:
        kind = read_varint(data, p)
        if kind is None:
            break
        frame_type, width = kind
        p += width
        if frame_type == _PADDING_FRAME:
            continue
        if frame_type == _PING_FRAME:
            continue
        if frame_type == _CRYPTO_FRAME:
            off = read_varint(data, p)
            if off is None:
                break
            offset, width = off
            p += width
            ln = read_varint(data, p)
            if ln is None:
                break
            length, width = ln
            p += width
            if p + length > n:
                break
            frames.append({"offset": offset, "data": bytes(data[p:p + length])})
            p += length
            continue
        break  # a frame type we do not model: stop cleanly
    return frames


def _reassemble_crypto(frames):
    """Concatenate CRYPTO frames by offset, dropping overlaps and duplicates."""
    out = bytearray()
    expected = 0
    for frame in sorted(frames, key=lambda f: f["offset"]):
        offset = frame["offset"]
        chunk = frame["data"]
        if offset > expected:
            break  # a gap we cannot fill: stop at the last contiguous byte
        if offset + len(chunk) <= expected:
            continue  # fully duplicate
        out += chunk[expected - offset:]
        expected = offset + len(chunk)
    return bytes(out)


def _find_client_hello(handshake):
    """Return the first TLS handshake message of type ClientHello (0x01)."""
    p = 0
    n = len(handshake)
    while p + 4 <= n:
        msg_type = handshake[p]
        length = int.from_bytes(handshake[p + 1:p + 4], "big")
        if p + 4 + length > n:
            break
        if msg_type == 0x01:
            return bytes(handshake[p:p + 4 + length])
        p += 4 + length
    return None



class CryptoAssembler:
    """Reassemble a QUIC CRYPTO stream across packets, per connection.

    A real ClientHello does not fit in one Initial packet. Traffic observed on
    an ordinary machine split a 1746-byte ClientHello across two Initials: the
    first carried CRYPTO at offset 0 with 1211 bytes, the second carried the
    remaining 535 at offset 1211. The RFC's own test vector fits in a single
    packet, so a reader that only ever looks at one datagram passes its test
    vector and still fingerprints nothing on a real network -- which is exactly
    what happened here until this class existed.

    Chunks are keyed by their stream offset and the stream is reassembled from
    offset 0 upwards, so a frame whose offset does not connect to the run
    already held is ignored rather than spliced in. Padding makes a decrypted
    Initial look like it contains further frames, and those spurious offsets
    are what this rule discards.
    """

    def __init__(self, max_connections=256, max_bytes=262144):
        self._streams = {}
        self.max_connections = max_connections
        self.max_bytes = max_bytes
        self.completed = 0
        self.dropped = 0

    def feed(self, datagram):
        """Take one UDP payload; return a completed ClientHello dict, or None.

        The returned dict is {'version', 'dcid', 'scid', 'client_hello',
        'packet_number'} and is shaped exactly like the one
        client_hello_from_datagram returns, so a caller can swap between them.
        """
        if not datagram or quic_unavailable():
            return None
        try:
            packets = parse_packets(datagram)
        except Exception:
            return None
        for packet in packets:
            if packet.get("packet_type") != "initial":
                continue
            try:
                keys = derive_initial_keys(packet["dcid"], packet["version"])
                decrypted = decrypt_initial(packet, keys)
            except Exception:
                # a server Initial or a 0-RTT packet uses different keys, and
                # most UDP is not QUIC at all: silence is correct here
                continue
            try:
                frames = crypto_frames(decrypted["plaintext"])
            except Exception:
                continue
            if not frames:
                continue
            stream = self._add(packet["dcid"], frames)
            if stream is None:
                continue
            hello = _complete_client_hello(stream)
            if hello is None:
                continue
            self.completed += 1
            self._streams.pop(packet["dcid"], None)
            return {
                "version": packet["version"],
                "dcid": packet["dcid"],
                "scid": packet["scid"],
                "packet_number": decrypted["packet_number"],
                "client_hello": hello,
            }
        return None

    def _add(self, dcid, frames):
        """Store the frames and return the contiguous stream from offset 0."""
        chunks = self._streams.get(dcid)
        if chunks is None:
            if len(self._streams) >= self.max_connections:
                # drop the oldest connection rather than growing without bound
                self._streams.pop(next(iter(self._streams)), None)
                self.dropped += 1
            chunks = self._streams[dcid] = {}
        for frame in frames:
            offset = frame.get("offset")
            data = frame.get("data") or b""
            if not isinstance(offset, int) or offset < 0 or not data:
                continue
            if offset in chunks:
                continue
            chunks[offset] = data

        buf = bytearray()
        position = 0
        while position in chunks:
            chunk = chunks[position]
            buf.extend(chunk)
            position += len(chunk)
            if len(buf) > self.max_bytes:
                self._streams.pop(dcid, None)
                self.dropped += 1
                return None
        return bytes(buf)


def _complete_client_hello(stream):
    """Return the ClientHello once the whole handshake message is present."""
    if len(stream) < 4 or stream[0] != 0x01:      # 0x01 is a ClientHello
        return None
    length = int.from_bytes(stream[1:4], "big")
    if length <= 0 or length > 65535:
        return None
    if len(stream) < 4 + length:
        return None                                # still arriving
    return stream[:4 + length]


def quic_unavailable():
    """True when this module cannot decrypt anything."""
    return not HAVE_CRYPTO

def extract_client_hello(packet, keys):
    """Decrypt ``packet``, reassemble its CRYPTO frames and return the TLS
    ClientHello handshake bytes (starting with 0x01), or None."""
    try:
        result = decrypt_initial(packet, keys)
    except QuicUnavailable:
        raise
    except Exception:
        return None
    frames = crypto_frames(result["plaintext"])
    if not frames:
        return None
    return _find_client_hello(_reassemble_crypto(frames))


def client_hello_from_datagram(datagram):
    """Convenience entry point: recover the ClientHello from a QUIC datagram.

    Walks the datagram's packets and returns, for the first Initial packet that
    decrypts, ``{'version', 'dcid', 'scid', 'client_hello', 'packet_number'}``.
    Returns None when nothing decrypts -- including when the crypto library is
    unavailable.  Never raises.
    """
    try:
        packets = parse_packets(datagram)
    except Exception:
        return None
    if not HAVE_CRYPTO:
        return None
    for packet in packets:
        if packet.get("packet_type") != "initial":
            continue
        version = packet.get("version")
        if version not in _SALT_BY_VERSION:
            continue
        try:
            keys = derive_initial_keys(packet["dcid"], version)
        except Exception:
            continue
        try:
            client_hello = extract_client_hello(packet, keys)
        except Exception:
            client_hello = None
        if client_hello is None:
            continue
        try:
            packet_number = decrypt_initial(packet, keys)["packet_number"]
        except Exception:
            packet_number = None
        return {
            "version": version,
            "dcid": packet["dcid"],
            "scid": packet["scid"],
            "client_hello": client_hello,
            "packet_number": packet_number,
        }
    return None
