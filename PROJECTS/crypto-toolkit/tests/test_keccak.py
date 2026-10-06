"""Keccak-f[1600] and the SHA-3 functions, checked against FIPS 202.

Two halves, as everywhere in this project. The first asserts the NIST CAVP
published vectors verbatim. The second compares against `hashlib`, which
implements the same standard independently, over lengths chosen to land on and
beside every rate boundary -- the sponge is where a bug hides, and a bug there
usually shows up only when a message fills a block exactly.
"""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

import pytest

from src.keccak import (
    KECCAK_LANES,
    SHA3_224_RATE,
    SHA3_256_RATE,
    SHA3_384_RATE,
    SHA3_512_RATE,
    SHAKE128_RATE,
    SHAKE256_RATE,
    _ROUND_CONSTANTS,
    _RHO,
    keccak_f1600,
    sha3_224,
    sha3_256,
    sha3_256_hex,
    sha3_384,
    sha3_512,
    shake_128,
    shake_256,
)

VECTORS = Path(__file__).parent / "vectors" / "cavp_sha3.json"

# The lengths where the sponge is least forgiving: each rate, and each rate
# plus or minus one byte. A message that fills a block exactly forces the
# padding into a block of its own, which is the case a hand-written sponge
# usually gets wrong.
BOUNDARY_LENGTHS = sorted({
    0, 1, 2, 3,
    SHA3_512_RATE - 1, SHA3_512_RATE, SHA3_512_RATE + 1,
    SHA3_384_RATE - 1, SHA3_384_RATE, SHA3_384_RATE + 1,
    SHA3_256_RATE - 1, SHA3_256_RATE, SHA3_256_RATE + 1,
    SHA3_224_RATE - 1, SHA3_224_RATE, SHA3_224_RATE + 1,
    SHAKE128_RATE - 1, SHAKE128_RATE, SHAKE128_RATE + 1,
    SHAKE256_RATE - 1, SHAKE256_RATE, SHAKE256_RATE + 1,
})


def _load_vectors() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def test_the_published_vectors_are_present_and_are_the_standards():
    doc = _load_vectors()
    assert "CAVP" in doc["_source"]
    assert set(doc["cases"]) == {"SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512"}
    assert sum(len(v) for v in doc["cases"].values()) >= 100


@pytest.mark.parametrize("algorithm", ["SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512"])
def test_cavp_published_vectors(algorithm):
    """The standard's own worked examples, asserted byte for byte.

    CAVP writes `Msg` zero-padded to a whole byte even when `Len` is not a
    multiple of eight, and `Len = 0` still carries `Msg = 00`. Truncating to
    `Len // 8` bytes is what the field means; only byte-aligned cases are
    vendored, because the module's API takes bytes.
    """
    function = {"SHA3_224": sha3_224, "SHA3_256": sha3_256,
                "SHA3_384": sha3_384, "SHA3_512": sha3_512}[algorithm]
    cases = _load_vectors()["cases"][algorithm]
    assert cases, f"no vendored vectors for {algorithm}"
    for case in cases:
        message = bytes.fromhex(case["msg"])[: case["len_bits"] // 8]
        assert len(message) == case["len_bits"] // 8
        assert function(message).hex() == case["md"], (
            f"{algorithm} on {case['len_bits']} bits: "
            f"{function(message).hex()} != {case['md']}"
        )


@pytest.mark.parametrize("length", BOUNDARY_LENGTHS)
def test_differential_against_hashlib(length):
    """An independent implementation of the same standard, on every rate edge."""
    rng = random.Random(0xF1600 + length)
    message = bytes(rng.randrange(256) for _ in range(length))
    assert sha3_224(message) == hashlib.sha3_224(message).digest()
    assert sha3_256(message) == hashlib.sha3_256(message).digest()
    assert sha3_384(message) == hashlib.sha3_384(message).digest()
    assert sha3_512(message) == hashlib.sha3_512(message).digest()


def test_differential_against_hashlib_over_random_messages():
    rng = random.Random(20261006)
    for _ in range(150):
        message = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 600)))
        assert sha3_256(message) == hashlib.sha3_256(message).digest()
        assert sha3_512(message) == hashlib.sha3_512(message).digest()


@pytest.mark.parametrize("out_length", [0, 1, 16, 32, 64, 135, 136, 137, 168, 169, 500, 4096])
def test_shake_outputs_exactly_the_requested_length(out_length):
    assert len(shake_128(b"message", out_length)) == out_length
    assert len(shake_256(b"message", out_length)) == out_length


@pytest.mark.parametrize("out_length", [0, 1, 16, 32, 64, 137, 168, 500, 4096])
def test_shake_differential_against_hashlib(out_length):
    for message in (b"", b"abc", bytes(range(200))):
        assert shake_128(message, out_length) == hashlib.shake_128(message).digest(out_length)
        assert shake_256(message, out_length) == hashlib.shake_256(message).digest(out_length)


def test_a_longer_output_is_a_prefix_extension_of_a_shorter_one():
    """An XOF squeezes, so asking for more must not change the first bytes.

    This is a property of the construction rather than a value, and it is the
    one thing that distinguishes a real sponge from a function that hashes the
    length into the input.
    """
    long_output = shake_128(b"prefix property", 400)
    for length in (1, 16, 32, 137, 168, 200):
        assert shake_128(b"prefix property", length) == long_output[:length]


def test_the_two_domains_do_not_collide():
    """SHA-3 and SHAKE differ only in domain separation, so it has to matter."""
    message = b"the same input to both"
    assert shake_256(message, 32) != sha3_256(message)
    assert shake_128(message, 32) != sha3_256(message)


def test_sha3_256_hex_is_the_digest_in_lowercase_hex():
    assert sha3_256_hex(b"abc") == sha3_256(b"abc").hex()
    assert sha3_256_hex(b"abc") == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"


def test_negative_output_length_is_refused():
    with pytest.raises(ValueError):
        shake_128(b"message", -1)
    with pytest.raises(ValueError):
        shake_256(b"message", -1)


def test_a_state_of_the_wrong_size_is_refused():
    with pytest.raises(ValueError):
        keccak_f1600([0] * (KECCAK_LANES - 1))
    with pytest.raises(ValueError):
        keccak_f1600([0] * (KECCAK_LANES + 1))


def _round_constants_from_the_standard() -> tuple[int, ...]:
    """FIPS 202 Algorithm 5, the rc(t) linear feedback shift register.

    RC[ir] is zero except at the bit positions 2**j - 1, which hold
    rc(j + 7*ir) for j in 0..6.
    """
    def rc(t: int) -> int:
        if t % 255 == 0:
            return 1
        r = [1, 0, 0, 0, 0, 0, 0, 0]
        for _ in range(1, t % 255 + 1):
            r = [0] + r
            r[0] ^= r[8]
            r[4] ^= r[8]
            r[5] ^= r[8]
            r[6] ^= r[8]
            r = r[:8]
        return r[0]

    constants = []
    for ir in range(24):
        value = 0
        for j in range(7):
            if rc(j + 7 * ir):
                value |= 1 << ((1 << j) - 1)
        constants.append(value)
    return tuple(constants)


def test_round_constants_are_derived_from_the_standard_lfsr():
    """Not "the table is right", but "the table is the standard's rule".

    Typing 24 constants from a document and typing them wrong look identical.
    Deriving them from the LFSR of the standard and comparing is what turns the
    table into something checked.
    """
    assert _round_constants_from_the_standard() == tuple(_ROUND_CONSTANTS)


def test_rho_offsets_are_derived_from_the_standard_walk():
    """FIPS 202 Section 3.2.2: start at (1,0) and walk (x,y) -> (y, 2x+3y).

    The offset for step t is (t+1)(t+2)/2 mod 64, and (0,0) is not rotated.
    """
    derived = {(0, 0): 0}
    x, y = 1, 0
    for t in range(24):
        derived[(x, y)] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    assert derived == {(x, y): _RHO[x][y] for x in range(5) for y in range(5)}
