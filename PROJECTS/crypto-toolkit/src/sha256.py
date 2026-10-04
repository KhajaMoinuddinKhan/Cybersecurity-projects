"""SHA-256, implemented from the FIPS 180-4 specification.

Everything here is built from the standard library alone.  The digest is
produced by the same compression function the specification describes: the
message is padded, split into 512-bit blocks, each block is expanded into a
64-word message schedule, and eight working variables are mixed through 64
rounds with the round constants below.

The round constants are not arbitrary.  They are the first 32 bits of the
fractional parts of the cube roots of the first 64 prime numbers, and the eight
initial working values are the first 32 bits of the fractional parts of the
square roots of the first eight primes.  The same numbers appear in the
specification as ``K`` and ``H``.  They are written out literally so the module
has no import-time computation to get wrong.
"""

from __future__ import annotations

import struct

SHA256_DIGEST_SIZE = 32
SHA256_BLOCK_SIZE = 64

# The first 32 bits of the fractional parts of the square roots of the first
# eight primes (2, 3, 5, 7, 11, 13, 17, 19).
_H0 = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)

# The first 32 bits of the fractional parts of the cube roots of the first
# 64 primes.
_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

_MASK = 0xFFFFFFFF


def _rotr(value: int, amount: int) -> int:
    """Rotate a 32-bit word right by ``amount`` bits."""
    return ((value >> amount) | (value << (32 - amount))) & _MASK


def _compress(state: list, block: bytes) -> None:
    """Mix one 64-byte block into the eight-word working ``state`` in place.

    The block is expanded into the 64-word schedule ``w`` (the first 16 words
    are read straight from the block; the rest are derived with the two sigma
    functions), then the eight working variables are rotated through the 64
    rounds.  ``state`` is updated with the round's result.
    """
    w = list(struct.unpack(">16I", block)) + [0] * 48
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _MASK

    a, b, c, d, e, f, g, h = state

    for i in range(64):
        big_s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ ((~e & _MASK) & g)
        temp1 = (h + big_s1 + ch + _K[i] + w[i]) & _MASK
        big_s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (big_s0 + maj) & _MASK

        h = g
        g = f
        f = e
        e = (d + temp1) & _MASK
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & _MASK

    state[0] = (state[0] + a) & _MASK
    state[1] = (state[1] + b) & _MASK
    state[2] = (state[2] + c) & _MASK
    state[3] = (state[3] + d) & _MASK
    state[4] = (state[4] + e) & _MASK
    state[5] = (state[5] + f) & _MASK
    state[6] = (state[6] + g) & _MASK
    state[7] = (state[7] + h) & _MASK


def _pad(data: bytes) -> bytes:
    """Append the mandatory padding to a complete message.

    A single ``0x80`` byte is appended, then zero bytes until the total length
    is 56 modulo 64, then the original length in *bits* as a 64-bit big-endian
    integer.  The length is taken from ``len(data)`` before the padding is
    added.
    """
    bit_length = len(data) * 8
    data = data + b"\x80"
    data += b"\x00" * ((56 - len(data)) % 64)
    data += struct.pack(">Q", bit_length & 0xFFFFFFFFFFFFFFFF)
    return data


def sha256(data: bytes) -> bytes:
    """Return the 32-byte SHA-256 digest of ``data``.

    The whole message is held in memory; :class:`SHA256` is the streaming
    alternative for input too large for that.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError("sha256() requires a bytes-like object")
    data = bytes(data)
    state = list(_H0)
    padded = _pad(data)
    for offset in range(0, len(padded), SHA256_BLOCK_SIZE):
        _compress(state, padded[offset:offset + SHA256_BLOCK_SIZE])
    return struct.pack(">8I", *state)


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 digest of ``data`` as 64 lowercase hex characters."""
    return sha256(data).hex()


class SHA256:
    """Streaming SHA-256 that consumes data one :meth:`update` at a time.

    The class keeps only the bytes that have not yet formed a full 64-byte
    block, so the caller never has to hold the whole message.  Feeding the same
    bytes in any split produces the same digest as :func:`sha256`.
    """

    def __init__(self) -> None:
        self._state = list(_H0)
        self._buffer = b""
        self._length = 0

    def update(self, data: bytes) -> "SHA256":
        """Absorb ``data`` and return ``self`` so calls can be chained."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ValueError("update() requires a bytes-like object")
        data = bytes(data)
        self._length += len(data)
        buffer = self._buffer + data
        end = len(buffer) - (len(buffer) % SHA256_BLOCK_SIZE)
        for offset in range(0, end, SHA256_BLOCK_SIZE):
            _compress(self._state, buffer[offset:offset + SHA256_BLOCK_SIZE])
        self._buffer = buffer[end:]
        return self

    def digest(self) -> bytes:
        """Return the digest of everything absorbed so far.

        The object is not modified: calling ``digest()`` twice, or calling
        ``update()`` afterwards, behaves as if the digest call never happened.
        """
        state = list(self._state)
        bit_length = self._length * 8
        tail = self._buffer + b"\x80"
        tail += b"\x00" * ((56 - len(tail)) % SHA256_BLOCK_SIZE)
        tail += struct.pack(">Q", bit_length & 0xFFFFFFFFFFFFFFFF)
        for offset in range(0, len(tail), SHA256_BLOCK_SIZE):
            _compress(state, tail[offset:offset + SHA256_BLOCK_SIZE])
        return struct.pack(">8I", *state)

    def hexdigest(self) -> str:
        """Return :meth:`digest` as 64 lowercase hex characters."""
        return self.digest().hex()

    def copy(self) -> "SHA256":
        """Return an independent object with the same absorbed state."""
        clone = SHA256.__new__(SHA256)
        clone._state = list(self._state)
        clone._buffer = self._buffer
        clone._length = self._length
        return clone
