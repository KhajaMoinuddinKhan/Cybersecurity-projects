"""HMAC-SHA256, as specified by RFC 2104 with SHA-256 as the hash.

HMAC turns a keyed hash into a message authentication code. The construction
is

    HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))

where H is SHA-256, K' is the key prepared for the hash's block size, and
ipad and opad are the constants 0x36 and 0x5c repeated to a full block. The
only subtle part is preparing K', so that step is kept as its own named
function rather than buried inside the digest computation.
"""

from __future__ import annotations

from .sha256 import sha256

# SHA-256 processes input in 64-byte blocks, so that is HMAC's block size.
BLOCK_SIZE = 64

# The two pad bytes from RFC 2104 section 2.
_IPAD = 0x36
_OPAD = 0x5C

__all__ = [
    "BLOCK_SIZE",
    "hmac_sha256",
    "hmac_sha256_hex",
    "constant_time_compare",
]


def _as_bytes(value: bytes, name: str) -> bytes:
    """Return *value* as an immutable bytes object, or raise ValueError.

    HMAC is defined over byte strings. Anything else - a str, an int, None -
    is a malformed input rather than a programming accident, so it is
    reported as ValueError to match the rest of the toolkit.
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise ValueError(f"{name} must be bytes, got {type(value).__name__}")


def _prepare_key(key: bytes) -> bytes:
    """Return the key reduced to exactly one block, ready to XOR with a pad.

    RFC 2104 allows a key of any length. Two cases have to be handled:

    * A key longer than the block size is hashed first, and the digest - now
      at most 32 bytes - is used in its place. This is why test 6 of the
      published vectors, with its 131-byte key, exists.
    * A key shorter than the block size is right-padded with zero bytes until
      it fills exactly one block. Zero-padding is not the same as repeating
      the key, and the short vectors will not catch a mistake here.
    """
    if len(key) > BLOCK_SIZE:
        key = sha256(key)
    if len(key) < BLOCK_SIZE:
        key = key + b"\x00" * (BLOCK_SIZE - len(key))
    return key


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Return the 32-byte HMAC-SHA256 tag of *message* under *key*.

    The key may be any length. A key longer than 64 bytes is hashed down
    first; a shorter key is zero-padded to 64 bytes.
    """
    key = _as_bytes(key, "key")
    message = _as_bytes(message, "message")

    block_key = _prepare_key(key)

    inner_pad = bytes(byte ^ _IPAD for byte in block_key)
    outer_pad = bytes(byte ^ _OPAD for byte in block_key)

    inner = sha256(inner_pad + message)
    return sha256(outer_pad + inner)


def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    """Return the HMAC-SHA256 tag of *message* as 64 lowercase hex characters."""
    return hmac_sha256(key, message).hex()


def constant_time_compare(left: bytes, right: bytes) -> bool:
    """Compare two byte strings without leaking where they first differ.

    The comparison XORs every pair of bytes and accumulates the results, so
    it runs the same instructions for a mismatch in the first byte and a
    mismatch in the last. Two values of different length are simply not
    equal and return False; the length itself is not secret.
    """
    left = _as_bytes(left, "left")
    right = _as_bytes(right, "right")

    if len(left) != len(right):
        return False

    difference = 0
    for a, b in zip(left, right, strict=True):
        difference |= a ^ b

    return difference == 0
