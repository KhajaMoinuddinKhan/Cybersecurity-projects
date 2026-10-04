"""AES-GCM, built on the AES block cipher in ``src/aes.py``.

GCM is two things bolted together. The first is counter mode: the plaintext is
XORed with a keystream produced by encrypting a sequence of counter blocks, so
the ciphertext has the same length as the plaintext and no padding is needed.
The second is a universal hash over GF(2**128) that turns the ciphertext and any
associated data into a tag, so a reader can tell that the message arrived intact
and that nobody added a field to it on the way.

The second half is the part worth reading. GHASH treats a 128-bit block as a
polynomial over GF(2) and multiplies it by a fixed value derived from the key,
so that any change to the input changes the product in a way an attacker cannot
predict without the key. The multiplication here is written out rather than
borrowed, because the bit ordering the specification chooses -- the most
significant bit of a byte is the coefficient of the highest power, and the
reduction polynomial is applied when the *low* bit of the running value is set
-- is the detail that makes a hand-written GCM produce plausible-looking tags
that verify against nothing.
"""
from __future__ import annotations

from .aes import AES, xor_bytes

GCM_BLOCK_SIZE = 16
GCM_TAG_SIZE = 16
GCM_NONCE_RECOMMENDED_SIZE = 12

# x**128 + x**7 + x**2 + x + 1, the reduction polynomial, as the low bit of the
# value is the x**127 coefficient and the wrap-around lands on x**128.
_REDUCTION = 0xE1000000000000000000000000000000


class InvalidTag(ValueError):
    """The tag did not match, so the ciphertext or the AAD was altered."""


def _gf_multiply(left: int, right: int) -> int:
    """Multiply two field elements, as GCM's GHASH defines the operation.

    Both arguments are 128-bit integers whose most significant bit is the
    coefficient of x**0 in the specification's notation. The loop walks the
    bits of ``left`` from the top, accumulating ``right`` shifted right by one
    each time, and applies the reduction polynomial whenever a bit falls off
    the bottom.
    """

    product = 0
    value = right
    for index in range(128):
        if (left >> (127 - index)) & 1:
            product ^= value
        if value & 1:
            value = (value >> 1) ^ _REDUCTION
        else:
            value >>= 1
    return product


def _to_block(data: bytes) -> int:
    return int.from_bytes(data, "big")


def ghash(h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """The GHASH of the associated data and the ciphertext, under ``h``.

    The input is the associated data, zero-padded to a block boundary, then the
    ciphertext, zero-padded, then a final block carrying the two lengths in
    *bits* as 64-bit big-endian integers -- the AAD length in the high half and
    the ciphertext length in the low half. Getting the padding or the units
    wrong produces a tag that is wrong for every message of any length, which is
    why the lengths are stated in bits here and nowhere else.
    """

    if len(h) != GCM_BLOCK_SIZE:
        raise ValueError("GHASH needs a 16-byte hash subkey")
    key = _to_block(h)
    accumulator = 0
    for offset in range(0, len(aad), GCM_BLOCK_SIZE):
        block = aad[offset:offset + GCM_BLOCK_SIZE].ljust(GCM_BLOCK_SIZE, b"\x00")
        accumulator = _gf_multiply(accumulator ^ _to_block(block), key)
    for offset in range(0, len(ciphertext), GCM_BLOCK_SIZE):
        block = ciphertext[offset:offset + GCM_BLOCK_SIZE].ljust(GCM_BLOCK_SIZE, b"\x00")
        accumulator = _gf_multiply(accumulator ^ _to_block(block), key)
    lengths = (len(aad) * 8) << 64 | (len(ciphertext) * 8)
    accumulator = _gf_multiply(accumulator ^ lengths, key)
    return accumulator.to_bytes(GCM_BLOCK_SIZE, "big")


def _increment32(block: bytes) -> bytes:
    """Increment the low 32 bits of a counter block, with wraparound.

    GCM's counter is a 32-bit counter sitting in the last four bytes of a
    128-bit block; the rest of the block is fixed for the whole message. That is
    why a message longer than 2**32 blocks is forbidden rather than handled.
    """

    low = (int.from_bytes(block[12:], "big") + 1) & 0xFFFFFFFF
    return block[:12] + low.to_bytes(4, "big")


class GCM:
    """Authenticated encryption under one AES key.

    ``encrypt`` returns the ciphertext and a 16-byte tag. ``decrypt`` verifies
    the tag before it does anything else and raises ``InvalidTag`` when it does
    not match, so a caller never receives plaintext that was not authenticated.
    """

    def __init__(self, key: bytes) -> None:
        self._aes = AES(key)
        # H is the encryption of the all-zero block: the key's contribution to
        # the hash, fixed for the lifetime of this object.
        self._h = self._aes.encrypt_block(b"\x00" * GCM_BLOCK_SIZE)

    @property
    def hash_subkey(self) -> bytes:
        return self._h

    def _initial_counter(self, nonce: bytes) -> bytes:
        """J0: the counter block the tag is computed under.

        A 96-bit nonce is the recommended size and gets a fast path -- the
        counter starts at one in the last four bytes. Any other length is hashed
        into a block first, which is the branch most implementations get wrong.
        """

        if not isinstance(nonce, (bytes, bytearray)):
            raise ValueError("the nonce must be bytes")
        if not nonce:
            raise ValueError("the nonce must be at least one byte")
        nonce = bytes(nonce)
        if len(nonce) == GCM_NONCE_RECOMMENDED_SIZE:
            return nonce + b"\x00\x00\x00\x01"
        key = _to_block(self._h)
        accumulator = 0
        for offset in range(0, len(nonce), GCM_BLOCK_SIZE):
            block = nonce[offset:offset + GCM_BLOCK_SIZE].ljust(GCM_BLOCK_SIZE, b"\x00")
            accumulator = _gf_multiply(accumulator ^ _to_block(block), key)
        # The final block is 64 zero bits followed by the nonce length in bits,
        # which is the one place GCM's length block is not in the AAD order.
        accumulator = _gf_multiply(accumulator ^ (len(nonce) * 8), key)
        return accumulator.to_bytes(GCM_BLOCK_SIZE, "big")

    def _counter_mode(self, initial_counter_block: bytes, data: bytes) -> bytes:
        """Encrypt or decrypt ``data`` under the counter, block by block."""

        if not data:
            return b""
        out = bytearray()
        counter = initial_counter_block
        for offset in range(0, len(data), GCM_BLOCK_SIZE):
            keystream = self._aes.encrypt_block(counter)
            chunk = data[offset:offset + GCM_BLOCK_SIZE]
            out += xor_bytes(chunk, keystream[:len(chunk)])
            counter = _increment32(counter)
        return bytes(out)

    def _tag(self, initial_counter_block: bytes, aad: bytes, ciphertext: bytes) -> bytes:
        return xor_bytes(
            self._aes.encrypt_block(initial_counter_block),
            ghash(self._h, aad, ciphertext),
        )

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        """Return ``(ciphertext, tag)`` for ``plaintext`` under ``nonce``."""

        if not isinstance(plaintext, (bytes, bytearray)):
            raise ValueError("the plaintext must be bytes")
        if not isinstance(aad, (bytes, bytearray)):
            raise ValueError("the associated data must be bytes")
        plaintext = bytes(plaintext)
        aad = bytes(aad)
        initial_counter = self._initial_counter(nonce)
        ciphertext = self._counter_mode(_increment32(initial_counter), plaintext)
        return ciphertext, self._tag(initial_counter, aad, ciphertext)

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        """Return the plaintext, or raise ``InvalidTag`` if the tag is wrong."""

        if not isinstance(ciphertext, (bytes, bytearray)):
            raise ValueError("the ciphertext must be bytes")
        if not isinstance(tag, (bytes, bytearray)):
            raise ValueError("the tag must be bytes")
        if not isinstance(aad, (bytes, bytearray)):
            raise ValueError("the associated data must be bytes")
        ciphertext = bytes(ciphertext)
        tag = bytes(tag)
        aad = bytes(aad)
        if len(tag) != GCM_TAG_SIZE:
            raise ValueError("the tag must be 16 bytes")
        initial_counter = self._initial_counter(nonce)
        expected = self._tag(initial_counter, aad, ciphertext)
        if not _constant_time_equal(expected, tag):
            raise InvalidTag("the tag does not match this ciphertext")
        return self._counter_mode(_increment32(initial_counter), ciphertext)


def _constant_time_equal(left: bytes, right: bytes) -> bool:
    """Compare two byte strings without stopping at the first difference."""

    if len(left) != len(right):
        return False
    difference = 0
    for a, b in zip(left, right):
        difference |= a ^ b
    return difference == 0
