"""Tests for src/hmac.py.

The published RFC 4231 vectors are asserted verbatim, and a differential test
compares the implementation against the standard library's hmac module over
random inputs that straddle every interesting key and message length. The
random test is what catches a wrong key-padding rule, since the short
published vectors cannot distinguish zero-padding from, say, repeating the
key.
"""

from __future__ import annotations

import hashlib
import hmac as stdlib_hmac
import random

import pytest

from src.hmac import (
    BLOCK_SIZE,
    constant_time_compare,
    hmac_sha256,
    hmac_sha256_hex,
)


# --------------------------------------------------------------------------
# 1. Published RFC 4231 vectors, asserted as full hex digests.
# --------------------------------------------------------------------------
# (key, message, expected digest). Test 6 is the longer-than-block-size key.
RFC_4231_VECTORS = [
    (
        b"\x0b" * 20,
        b"Hi There",
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    ),
    (
        b"Jefe",
        b"what do ya want for nothing?",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    ),
    (
        b"\xaa" * 20,
        b"\xdd" * 50,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    ),
    (
        bytes.fromhex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
        b"\xcd" * 50,
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    ),
    (
        b"\xaa" * 131,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    ),
]


@pytest.mark.parametrize("key,message,digest", RFC_4231_VECTORS)
def test_rfc4231_vectors(key, message, digest):
    assert hmac_sha256_hex(key, message) == digest
    assert hmac_sha256(key, message) == bytes.fromhex(digest)
    assert len(hmac_sha256(key, message)) == 32


def test_rfc4231_test6_key_is_longer_than_block():
    """Guard the case the task calls out: a key over one block is hashed."""
    key = b"\xaa" * 131
    assert len(key) > BLOCK_SIZE
    # Hashing the key first is what makes this vector come out right; a naive
    # implementation that just truncates or pads would miss it.
    assert hmac_sha256_hex(
        key, b"Test Using Larger Than Block-Size Key - Hash Key First"
    ) == "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"


# --------------------------------------------------------------------------
# 2. Differential test against the reference implementation.
# --------------------------------------------------------------------------
BOUNDARY_LENGTHS = [0, 1, 63, 64, 65, 127, 128, 129]


def _reference(key: bytes, message: bytes) -> bytes:
    return stdlib_hmac.new(key, message, hashlib.sha256).digest()


@pytest.mark.parametrize("key_len", BOUNDARY_LENGTHS)
@pytest.mark.parametrize("msg_len", BOUNDARY_LENGTHS)
def test_boundary_lengths_match_reference(key_len, msg_len):
    # Deterministic byte strings of exactly key_len and msg_len bytes.
    key = bytes((i * 7 + 3) % 256 for i in range(key_len))
    message = bytes((i * 11 + 5) % 256 for i in range(msg_len))
    assert hmac_sha256(key, message) == _reference(key, message)


def test_differential_against_stdlib_hmac():
    """Thousands of random cases, key length 0..200, message length 0..300.

    A fixed seed keeps a failure reproducible. Boundary lengths are injected
    into the stream so they are guaranteed to appear alongside the random
    draws.
    """
    rng = random.Random(0xC0FFEE)

    cases = 0

    # Explicitly cover every combination of the boundary lengths first.
    for key_len in BOUNDARY_LENGTHS:
        for msg_len in BOUNDARY_LENGTHS:
            key = bytes(rng.randrange(256) for _ in range(key_len))
            message = bytes(rng.randrange(256) for _ in range(msg_len))
            assert hmac_sha256(key, message) == _reference(key, message), (
                f"mismatch at key_len={key_len} msg_len={msg_len}"
            )
            cases += 1

    # Then a few thousand fully random cases.
    for _ in range(3000):
        key_len = rng.randrange(0, 201)      # 0 to 200 inclusive
        msg_len = rng.randrange(0, 301)      # 0 to 300 inclusive
        key = bytes(rng.randrange(256) for _ in range(key_len))
        message = bytes(rng.randrange(256) for _ in range(msg_len))
        assert hmac_sha256(key, message) == _reference(key, message), (
            f"mismatch at key_len={key_len} msg_len={msg_len}"
        )
        cases += 1

    # Sanity check on the volume of the sweep, so a silently shrunken loop
    # does not pass as a green run.
    assert cases >= 3000


# --------------------------------------------------------------------------
# 3. constant_time_compare.
# --------------------------------------------------------------------------
def test_constant_time_compare_equal():
    assert constant_time_compare(b"correct horse", b"correct horse") is True


def test_constant_time_compare_differs_first_byte():
    assert constant_time_compare(b"\x00abc", b"\x01abc") is False


def test_constant_time_compare_differs_last_byte():
    assert constant_time_compare(b"abc\x00", b"abc\x01") is False


def test_constant_time_compare_different_lengths():
    assert constant_time_compare(b"abc", b"abcd") is False
    assert constant_time_compare(b"", b"a") is False


def test_constant_time_compare_empty_vs_empty():
    assert constant_time_compare(b"", b"") is True


def test_constant_time_compare_single_bit_difference():
    assert constant_time_compare(b"\x00" * 32, b"\x00" * 31 + b"\x80") is False


# --------------------------------------------------------------------------
# 4. Malformed input raises ValueError, not TypeError or a crash.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("bad_key", ["a string", 123, None, ["b"], object()])
def test_hmac_bad_key_raises_value_error(bad_key):
    with pytest.raises(ValueError):
        hmac_sha256(bad_key, b"message")


@pytest.mark.parametrize("bad_message", ["a string", 123, None, ["b"], object()])
def test_hmac_bad_message_raises_value_error(bad_message):
    with pytest.raises(ValueError):
        hmac_sha256(b"key", bad_message)


@pytest.mark.parametrize("bad", ["a string", 123, None, object()])
def test_constant_time_compare_bad_input_raises_value_error(bad):
    with pytest.raises(ValueError):
        constant_time_compare(bad, b"x")
    with pytest.raises(ValueError):
        constant_time_compare(b"x", bad)


def test_bytes_like_inputs_are_accepted():
    """bytearray and memoryview are legitimate byte strings, not errors."""
    expected = hmac_sha256(b"key", b"message")
    assert hmac_sha256(bytearray(b"key"), memoryview(b"message")) == expected
    assert hmac_sha256_hex(bytearray(b"key"), b"message") == expected.hex()
