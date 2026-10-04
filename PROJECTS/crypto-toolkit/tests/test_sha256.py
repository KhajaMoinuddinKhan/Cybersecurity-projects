"""Tests for src/sha256.py.

The published FIPS 180-4 vectors are asserted verbatim, the implementation is
then cross-checked against hashlib (the reference implementation shipped with
the standard library) over thousands of random messages, and the streaming
class is checked against the one-shot function, including at the padding
boundary lengths where the two paths are easiest to get wrong.
"""

from __future__ import annotations

import hashlib
import random

import pytest

from src.sha256 import SHA256, SHA256_DIGEST_SIZE, sha256, sha256_hex


# The FIPS 180-4 published vectors, from INTERFACES.md.
FIPS_VECTORS = [
    (
        b"",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        b"abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
]


@pytest.mark.parametrize("data, expected", FIPS_VECTORS)
def test_fips_180_4_vectors(data, expected):
    assert sha256(data).hex() == expected


@pytest.mark.parametrize("data, expected", FIPS_VECTORS)
def test_fips_vectors_via_streaming_class(data, expected):
    digest = SHA256().update(data).hexdigest()
    assert digest == expected


def test_digest_size_and_hex_form():
    assert SHA256_DIGEST_SIZE == 32
    assert len(sha256(b"anything")) == 32
    hexed = sha256_hex(b"anything")
    assert len(hexed) == 64
    assert hexed == hexed.lower()
    assert all(c in "0123456789abcdef" for c in hexed)


def test_one_million_a():
    # The published long-message vector: one million repetitions of "a".
    digest = sha256(b"a" * 1_000_000).hex()
    assert digest == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"


# Fixed seed so the differential test is reproducible.
_RANDOM_SEED = 0xC0FFEE


def _random_inputs(count, max_length=300, seed=_RANDOM_SEED):
    rng = random.Random(seed)
    return [rng.randbytes(rng.randint(0, max_length)) for _ in range(count)]


def test_differential_against_hashlib():
    # A few thousand random inputs of random length 0..300 bytes, compared with
    # the standard library's reference implementation.  This is the test that
    # catches a padding bug the published vectors do not exercise.
    inputs = _random_inputs(3000)
    for data in inputs:
        assert sha256(data) == hashlib.sha256(data).digest()


def test_differential_against_hashlib_streaming():
    # The same corpus, fed through the streaming class in random-sized chunks,
    # must equal both the one-shot function and hashlib.
    rng = random.Random(_RANDOM_SEED ^ 0x1234)
    for data in _random_inputs(3000):
        hasher = SHA256()
        offset = 0
        while offset < len(data):
            step = rng.randint(1, 40)
            hasher.update(data[offset:offset + step])
            offset += step
        expected = hashlib.sha256(data).digest()
        assert hasher.digest() == expected
        assert hasher.digest() == sha256(data)


BOUNDARY_LENGTHS = [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128]


@pytest.mark.parametrize("length", BOUNDARY_LENGTHS)
def test_padding_boundary_lengths(length):
    # Lengths straddling the 55/56-byte and 63/64-byte padding boundaries,
    # where the padding rule changes how many blocks the message occupies.
    data = bytes(range(256))[:1] * length if length else b""
    data = bytes((i * 7 + 3) & 0xFF for i in range(length))
    expected = hashlib.sha256(data).digest()
    assert sha256(data) == expected

    # Split at every possible point for these short inputs, plus a few
    # uneven chunkings, so the streaming buffer is exercised hard.
    for split in range(length + 1):
        hasher = SHA256()
        hasher.update(data[:split])
        hasher.update(data[split:])
        assert hasher.digest() == expected

    chunked = SHA256()
    step = 3
    for offset in range(0, length, step):
        chunked.update(data[offset:offset + step])
    assert chunked.digest() == expected


def test_streaming_matches_one_shot_for_boundaries():
    # An explicit, readable version of the boundary check above.
    for length in BOUNDARY_LENGTHS:
        data = bytes((i * 31 + 7) & 0xFF for i in range(length))
        expected = sha256(data)
        hasher = SHA256()
        # Feed one byte at a time to stress the internal buffer.
        for byte in data:
            hasher.update(bytes([byte]))
        assert hasher.digest() == expected


def test_copy_is_independent():
    # Digest a prefix, copy, then diverge: both branches must stay correct.
    prefix = b"the quick brown fox "
    branch_a = b"jumps over the lazy dog"
    branch_b = b"and then goes back to sleep"

    original = SHA256()
    original.update(prefix)
    snapshot = original.copy()

    # The snapshot must already match the prefix on its own.
    assert snapshot.digest() == hashlib.sha256(prefix).digest()

    original.update(branch_a)
    snapshot.update(branch_b)

    assert original.digest() == hashlib.sha256(prefix + branch_a).digest()
    assert snapshot.digest() == hashlib.sha256(prefix + branch_b).digest()

    # Mutating one object must not have touched the other.
    assert original.digest() != snapshot.digest()


def test_copy_of_empty_and_of_full_block():
    for prefill in (b"", b"x" * 64, b"y" * 100):
        hasher = SHA256()
        if prefill:
            hasher.update(prefill)
        clone = hasher.copy()
        hasher.update(b"left")
        clone.update(b"right")
        assert hasher.digest() == hashlib.sha256(prefill + b"left").digest()
        assert clone.digest() == hashlib.sha256(prefill + b"right").digest()


def test_digest_does_not_consume_state():
    # digest() must be repeatable and must not stop further updates.
    hasher = SHA256().update(b"abc")
    first = hasher.digest()
    second = hasher.digest()
    assert first == second == sha256(b"abc")
    hasher.update(b"def")
    assert hasher.digest() == sha256(b"abcdef")


def test_update_returns_self_and_chains():
    hasher = SHA256()
    assert hasher.update(b"a") is hasher
    assert hasher.update(b"b").update(b"c").hexdigest() == sha256_hex(b"abc")


def test_rejects_non_bytes():
    with pytest.raises(ValueError):
        sha256("not bytes")
    with pytest.raises(ValueError):
        SHA256().update("not bytes")
