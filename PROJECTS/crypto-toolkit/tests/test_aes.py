"""Tests for the from-scratch AES implementation.

Three kinds of check, in increasing order of how much they prove:

* the published FIPS-197 and NIST SP 800-38A vectors, asserted byte for byte;
* structural properties (CTR is symmetric, the counter wraps, malformed input
  is rejected with ValueError);
* a differential sweep against the ``cryptography`` reference implementation on
  random keys, blocks and lengths, which is what catches an implementation that
  happens to satisfy the published vectors but is wrong elsewhere.

``cryptography`` is a test oracle only.  It is imported inside the one test
that needs it, so the rest of the suite runs with nothing but the standard
library, and nothing under ``src/`` ever touches it.
"""

from __future__ import annotations

import random

import pytest

from src.aes import (
    AES,
    AES_BLOCK_SIZE,
    CTR,
    ctr_keystream,
    xor_bytes,
)


def h(hex_string: str) -> bytes:
    """Decode a hex string into bytes; keeps the vectors readable."""
    return bytes.fromhex(hex_string)


# ---------------------------------------------------------------------------
# FIPS-197 known-answer vectors
# ---------------------------------------------------------------------------
# Appendix B and Appendix C.1 / C.3 of FIPS-197.  Each case is checked in both
# directions: encrypting the plaintext gives the published ciphertext, and
# decrypting the published ciphertext gives the plaintext back.

FIPS_197_VECTORS = [
    # (key, plaintext, ciphertext) - AES-128 (C.1), AES-128 (B), AES-256 (C.3)
    (
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a",
    ),
    (
        "2b7e151628aed2a6abf7158809cf4f3c",
        "3243f6a8885a308d313198a2e0370734",
        "3925841d02dc09fbdc118597196a0b32",
    ),
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff",
        "8ea2b7ca516745bfeafc49904b496089",
    ),
]


@pytest.mark.parametrize("key_hex,plain_hex,cipher_hex", FIPS_197_VECTORS)
def test_fips_197_encrypt(key_hex, plain_hex, cipher_hex):
    cipher = AES(h(key_hex))
    assert cipher.encrypt_block(h(plain_hex)) == h(cipher_hex)


@pytest.mark.parametrize("key_hex,plain_hex,cipher_hex", FIPS_197_VECTORS)
def test_fips_197_decrypt(key_hex, plain_hex, cipher_hex):
    cipher = AES(h(key_hex))
    assert cipher.decrypt_block(h(cipher_hex)) == h(plain_hex)


def test_fips_197_ecb_buffer_round_trip():
    """The ECB buffer form agrees with the single-block form on every vector."""
    for key_hex, plain_hex, cipher_hex in FIPS_197_VECTORS:
        cipher = AES(h(key_hex))
        assert cipher.encrypt(h(plain_hex)) == h(cipher_hex)
        assert cipher.decrypt(h(cipher_hex)) == h(plain_hex)


# ---------------------------------------------------------------------------
# NIST SP 800-38A F.5.1 - AES-128-CTR
# ---------------------------------------------------------------------------
# One key, one initial counter block, four 16-byte plaintext blocks.  We assert
# all four blocks of ciphertext, plus the keystream that produces them, plus the
# streaming CTR class, so a counter that fails to increment between blocks shows
# up immediately.

SP800_38A_CTR_KEY = "2b7e151628aed2a6abf7158809cf4f3c"
SP800_38A_CTR_COUNTER = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
SP800_38A_CTR_PLAINTEXT = (
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
SP800_38A_CTR_CIPHERTEXT = (
    "874d6191b620e3261bef6864990db6ce"
    "9806f66b7970fdff8617187bb9fffdff"
    "5ae4df3edbd5d35e5b4f09020db03eab"
    "1e031dda2fbe03d1792170a0f3009cee"
)


def test_sp800_38a_ctr_keystream_matches_vector():
    plaintext = h(SP800_38A_CTR_PLAINTEXT)
    expected = h(SP800_38A_CTR_CIPHERTEXT)

    keystream = ctr_keystream(
        h(SP800_38A_CTR_KEY), h(SP800_38A_CTR_COUNTER), len(plaintext)
    )
    assert len(keystream) == len(plaintext) == 64
    assert xor_bytes(keystream, plaintext) == expected

    # The four ciphertext blocks, one by one, so a failure names the block.
    for block_index in range(4):
        start = block_index * AES_BLOCK_SIZE
        end = start + AES_BLOCK_SIZE
        assert xor_bytes(keystream[start:end], plaintext[start:end]) == expected[start:end]


def test_sp800_38a_ctr_class_matches_vector():
    cipher = CTR(h(SP800_38A_CTR_KEY), h(SP800_38A_CTR_COUNTER))
    assert cipher.update(h(SP800_38A_CTR_PLAINTEXT)) == h(SP800_38A_CTR_CIPHERTEXT)


def test_sp800_38a_ctr_class_decrypts_by_re_encrypting():
    ciphertext = h(SP800_38A_CTR_CIPHERTEXT)
    cipher = CTR(h(SP800_38A_CTR_KEY), h(SP800_38A_CTR_COUNTER))
    assert cipher.update(ciphertext) == h(SP800_38A_CTR_PLAINTEXT)


def test_sp800_38a_ctr_chunked_updates_agree_with_one_shot():
    """Feeding the data in arbitrary pieces must not change the answer."""
    plaintext = h(SP800_38A_CTR_PLAINTEXT)
    expected = h(SP800_38A_CTR_CIPHERTEXT)

    cipher = CTR(h(SP800_38A_CTR_KEY), h(SP800_38A_CTR_COUNTER))
    pieces = [plaintext[:1], plaintext[1:17], plaintext[17:40], plaintext[40:]]
    got = b"".join(cipher.update(piece) for piece in pieces)
    assert got == expected


# ---------------------------------------------------------------------------
# Differential test against the reference implementation
# ---------------------------------------------------------------------------

def test_matches_reference_implementation():
    """Compare random keys, blocks and CTR lengths with ``cryptography``.

    A fixed seed keeps a failure reproducible.  The sweep covers all three key
    sizes, ECB blocks (single and multi-block) and CTR over lengths that are not
    multiples of the block size, which is where an off-by-one in the counter or
    a bad partial-block slice would surface.
    """
    # The reference implementation is a declared test dependency, so a missing
    # one is a failure rather than a skip: a differential test that quietly does
    # nothing is worse than no test at all.
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        pytest.fail(
            "the differential test needs the reference implementation that "
            "requirements.txt declares: %s" % exc
        )

    rng = random.Random(0x5EED_A1CE)
    iterations = 300

    for _ in range(iterations):
        key_length = rng.choice((16, 24, 32))
        key = bytes(rng.getrandbits(8) for _ in range(key_length))
        aes = AES(key)

        # -- ECB: one random block ------------------------------------------
        block = bytes(rng.getrandbits(8) for _ in range(AES_BLOCK_SIZE))
        enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        reference_ct = enc.update(block) + enc.finalize()
        ours_ct = aes.encrypt_block(block)
        assert ours_ct == reference_ct, f"ECB encrypt mismatch for key {key.hex()}"

        dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        reference_pt = dec.update(reference_ct) + dec.finalize()
        assert aes.decrypt_block(ours_ct) == reference_pt
        assert aes.decrypt_block(ours_ct) == block

        # -- ECB: a whole multi-block buffer --------------------------------
        blocks = rng.randrange(1, 5)
        data = bytes(rng.getrandbits(8) for _ in range(AES_BLOCK_SIZE * blocks))
        enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        reference_buf = enc.update(data) + enc.finalize()
        assert aes.encrypt(data) == reference_buf
        assert aes.decrypt(reference_buf) == data

        # -- CTR: a random length, including partial final blocks -----------
        length = rng.randrange(0, 200)
        payload = bytes(rng.getrandbits(8) for _ in range(length))
        counter_block = bytes(rng.getrandbits(8) for _ in range(AES_BLOCK_SIZE))

        enc = Cipher(algorithms.AES(key), modes.CTR(counter_block)).encryptor()
        reference_ctr = enc.update(payload) + enc.finalize()

        keystream = ctr_keystream(key, counter_block, length)
        assert xor_bytes(keystream, payload) == reference_ctr
        assert CTR(key, counter_block).update(payload) == reference_ctr
        # Decryption is the same call with the ciphertext.
        assert CTR(key, counter_block).update(reference_ctr) == payload


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------
# Every one of these must raise ValueError - not IndexError, not struct.error,
# not a bare assert.

def test_malformed_key_length_is_value_error():
    for length in (0, 1, 15, 17, 23, 25, 31, 33, 64):
        with pytest.raises(ValueError):
            AES(bytes(length))


def test_malformed_block_length_is_value_error():
    aes = AES(bytes(16))
    for length in (0, 1, 15, 17, 32):
        with pytest.raises(ValueError):
            aes.encrypt_block(bytes(length))
        with pytest.raises(ValueError):
            aes.decrypt_block(bytes(length))


def test_malformed_buffer_length_is_value_error():
    aes = AES(bytes(16))
    for length in (1, 15, 17, 31, 33):
        with pytest.raises(ValueError):
            aes.encrypt(bytes(length))
        with pytest.raises(ValueError):
            aes.decrypt(bytes(length))


def test_malformed_counter_block_is_value_error():
    with pytest.raises(ValueError):
        ctr_keystream(bytes(16), bytes(15), 16)
    with pytest.raises(ValueError):
        ctr_keystream(bytes(16), bytes(17), 16)
    with pytest.raises(ValueError):
        CTR(bytes(16), bytes(15))
    with pytest.raises(ValueError):
        CTR(bytes(16), bytes(0))


def test_malformed_ctr_length_is_value_error():
    with pytest.raises(ValueError):
        ctr_keystream(bytes(16), bytes(16), -1)


def test_mismatched_xor_lengths_is_value_error():
    with pytest.raises(ValueError):
        xor_bytes(b"\x00\x01", b"\x00")


# ---------------------------------------------------------------------------
# Counter wraparound
# ---------------------------------------------------------------------------

def test_counter_wraps_instead_of_raising():
    """An all-0xff counter must roll over to zero for the next block."""
    key = bytes(16)
    counter_block = b"\xff" * AES_BLOCK_SIZE

    first = AES(key).encrypt_block(b"\xff" * AES_BLOCK_SIZE)
    second = AES(key).encrypt_block(b"\x00" * AES_BLOCK_SIZE)

    keystream = ctr_keystream(key, counter_block, 2 * AES_BLOCK_SIZE)
    assert keystream == first + second

    # The streaming class has to agree with the one-shot helper.
    assert CTR(key, counter_block).update(bytes(2 * AES_BLOCK_SIZE)) == first + second


# ---------------------------------------------------------------------------
# A few structural properties
# ---------------------------------------------------------------------------

def test_block_size_constant():
    assert AES_BLOCK_SIZE == 16


def test_key_sizes_are_reported():
    assert AES(bytes(16)).key_size == 128
    assert AES(bytes(24)).key_size == 192
    assert AES(bytes(32)).key_size == 256


def test_round_counts_follow_the_key_size():
    """10 / 12 / 14 rounds, as FIPS-197 defines them (Nk + 6)."""
    assert AES(bytes(16))._rounds == 10
    assert AES(bytes(24))._rounds == 12
    assert AES(bytes(32))._rounds == 14


def test_ecb_round_trip_on_random_buffer():
    aes = AES(bytes(range(16)))
    data = bytes(range(256)) * 3  # 768 bytes, a multiple of 16
    assert aes.decrypt(aes.encrypt(data)) == data


def test_ctr_update_with_empty_data_is_identity():
    cipher = CTR(bytes(16), bytes(16))
    assert cipher.update(b"") == b""


def test_xor_bytes_basic():
    assert xor_bytes(b"\x00\xff\x0f", b"\xff\xff\xf0") == b"\xff\x00\xff"
    assert xor_bytes(b"", b"") == b""
