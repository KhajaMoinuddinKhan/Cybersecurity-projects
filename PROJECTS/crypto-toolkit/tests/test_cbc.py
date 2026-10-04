"""AES-CBC against the published vectors and against a reference implementation.

The tests here come in the same two halves the other modules use, and they
answer different questions.  The NIST SP 800-38A vectors say this implementation
agrees with the standard on the cases the standard chose to write down -- one
key per size, four blocks, one IV.  The differential sweep says it agrees with
an independent implementation on several hundred inputs nobody chose, including
the awkward ones: empty input, lengths one byte on either side of a block
boundary, and every key size.

The second half is the one that catches a real bug.  A CBC implementation can
reproduce all three published vectors -- each is exactly four blocks long, with
the IV XORed into the first block -- while getting the *chaining* subtly wrong
in a way those vectors never exercise.  Comparing against ``cryptography`` over
random keys and lengths is what makes a chaining error visible.

``cryptography`` is a test oracle only.  It is imported inside the one test that
needs it, and nothing under ``src/`` ever touches it.
"""

import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.aes import AES, xor_bytes  # noqa: E402
from src.cbc import (  # noqa: E402
    CBC,
    CBC_BLOCK_SIZE,
    PaddingError,
    pkcs7_pad,
    pkcs7_unpad,
)


def h(text: str) -> bytes:
    """Decode a whitespace-separated hex string into bytes."""

    return bytes.fromhex("".join(text.split()))


# ---------------------------------------------------------------------------
# NIST SP 800-38A appendix F.2 - the published CBC vectors
# ---------------------------------------------------------------------------
# All three cases share one IV and one set of four plaintext blocks; only the
# key and the resulting ciphertext differ.  F.2.1/F.2.3/F.2.5 are the encrypt
# direction and F.2.2/F.2.4/F.2.6 the decrypt direction over the same pair, so
# each vector is asserted through both ``encrypt_blocks`` and ``decrypt_blocks``.
# The values were read out of the standard's text, not from this code.

SP800_38A_IV = "000102030405060708090a0b0c0d0e0f"
SP800_38A_PLAINTEXT = (
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)

# (name, key, ciphertext)
SP800_38A_CBC_VECTORS = [
    (
        "F.2.1/F.2.2 AES-128",
        "2b7e151628aed2a6abf7158809cf4f3c",
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7",
    ),
    (
        "F.2.3/F.2.4 AES-192",
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "4f021db243bc633d7178183a9fa071e8"
        "b4d9ada9ad7dedf4e5e738763f69145a"
        "571b242012fb7ae07fa9baac3df102e0"
        "08b0e27988598881d920a9e64f5615cd",
    ),
    (
        "F.2.5/F.2.6 AES-256",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
        "9cfc4e967edb808d679f777bc6702c7d"
        "39f23369a9d9bacfa530e26304231461"
        "b2eb05e2c39be9fcda6c19078c6a9d1b",
    ),
]


@pytest.mark.parametrize(
    "name,key_hex,cipher_hex",
    SP800_38A_CBC_VECTORS,
    ids=[vector[0] for vector in SP800_38A_CBC_VECTORS],
)
def test_the_published_vectors_encrypt(name, key_hex, cipher_hex):
    """Encrypting the four plaintext blocks gives exactly the published bytes."""

    cipher = CBC(h(key_hex))
    produced = cipher.encrypt_blocks(h(SP800_38A_IV), h(SP800_38A_PLAINTEXT))
    assert produced == h(cipher_hex), name


@pytest.mark.parametrize(
    "name,key_hex,cipher_hex",
    SP800_38A_CBC_VECTORS,
    ids=[vector[0] for vector in SP800_38A_CBC_VECTORS],
)
def test_the_published_vectors_decrypt(name, key_hex, cipher_hex):
    """Decrypting the published ciphertext returns the published plaintext."""

    cipher = CBC(h(key_hex))
    recovered = cipher.decrypt_blocks(h(SP800_38A_IV), h(cipher_hex))
    assert recovered == h(SP800_38A_PLAINTEXT), name


def test_the_published_vectors_hold_block_by_block():
    """Every one of the four ciphertext blocks must match on its own.

    A failure in the middle of the message rather than at its start points at
    the chaining step, not at AES, so it is worth naming the block.
    """

    plaintext = h(SP800_38A_PLAINTEXT)
    for name, key_hex, cipher_hex in SP800_38A_CBC_VECTORS:
        cipher = CBC(h(key_hex))
        expected = h(cipher_hex)
        for block_index in range(4):
            start = block_index * CBC_BLOCK_SIZE
            end = start + CBC_BLOCK_SIZE
            produced = cipher.encrypt_blocks(h(SP800_38A_IV), plaintext[:end])
            assert produced[start:end] == expected[start:end], (name, block_index)


# ---------------------------------------------------------------------------
# PKCS#7 padding
# ---------------------------------------------------------------------------

def test_padding_a_full_block_adds_a_whole_extra_block():
    """A message that already fits the grid still grows by a full block.

    The padding count is ``block_size - (length % block_size)``, and for a full
    block the remainder is zero, so the count is the block size itself.  If it
    came out zero instead, the last byte of a padded message could not be
    trusted to describe the padding.
    """

    data = bytes(range(16))
    padded = pkcs7_pad(data)
    assert len(padded) == 32
    assert padded[:16] == data
    assert padded[16:] == bytes([16]) * 16


def test_padding_of_nothing_is_a_full_block_of_sixteens():
    assert pkcs7_pad(b"") == bytes([16]) * 16


@pytest.mark.parametrize("length", list(range(0, 33)))
def test_padding_length_is_the_value_appended(length):
    """The appended byte states its own count, for every length up to two blocks."""

    data = bytes(length)
    expected_count = 16 - (length % 16)
    padded = pkcs7_pad(data)
    assert len(padded) == length + expected_count
    assert padded[-expected_count:] == bytes([expected_count]) * expected_count
    assert padded[:length] == data


@pytest.mark.parametrize("length", list(range(0, 65)))
def test_padding_round_trips_for_every_length_up_to_64(length):
    """Pad then unpad returns the original, on and off every block boundary."""

    data = bytes((index * 7 + 3) & 0xFF for index in range(length))
    assert pkcs7_unpad(pkcs7_pad(data)) == data


def test_unpad_rejects_a_zero_last_byte():
    """A zero length is not a legal padding count, so it is refused."""

    with pytest.raises(PaddingError):
        pkcs7_unpad(bytes(15) + b"\x00")


@pytest.mark.parametrize("bad_length", [17, 18, 32, 255])
def test_unpad_rejects_a_last_byte_larger_than_the_block_size(bad_length):
    with pytest.raises(PaddingError):
        pkcs7_unpad(bytes(15) + bytes([bad_length]))


def test_unpad_rejects_trailing_bytes_that_do_not_match():
    """Checking only the last byte would accept a message padded by an attacker."""

    # The last byte claims four bytes of padding, but the four trailing bytes
    # are 04 03 04 04 -- not all the same value.
    with pytest.raises(PaddingError):
        pkcs7_unpad(b"\x04\x03\x04\x04" + bytes(12))


def test_unpad_rejects_data_that_is_not_a_whole_number_of_blocks():
    with pytest.raises(PaddingError):
        pkcs7_unpad(bytes(15))            # 15, not a whole block
    with pytest.raises(PaddingError):
        pkcs7_unpad(bytes(17))            # 17, not a whole block
    with pytest.raises(PaddingError):
        pkcs7_unpad(b"")                  # nothing to unpad


# ---------------------------------------------------------------------------
# The padded convenience API
# ---------------------------------------------------------------------------

def test_encrypt_and_decrypt_round_trip_on_and_off_the_block_grid():
    rnd = random.Random(0xCBC0FFEE)
    key = bytes(rnd.getrandbits(8) for _ in range(16))
    iv = bytes(rnd.getrandbits(8) for _ in range(16))
    cipher = CBC(key)
    for length in (0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257, 1000):
        plaintext = bytes(rnd.getrandbits(8) for _ in range(length))
        ciphertext = cipher.encrypt(iv, plaintext)
        # The ciphertext is the padded plaintext rounded up to a block, and it
        # is always longer than the plaintext by at least one byte.
        assert len(ciphertext) % CBC_BLOCK_SIZE == 0
        assert len(ciphertext) > length
        assert cipher.decrypt(iv, ciphertext) == plaintext


def test_decrypt_blocks_returns_the_padding_untouched():
    """The raw form is what a padding oracle reads, so it must not strip anything."""

    key = bytes(range(16))
    iv = bytes(16)
    cipher = CBC(key)
    message = b"a message that does not end on a block boundary"
    ciphertext = cipher.encrypt(iv, message)

    raw = cipher.decrypt_blocks(iv, ciphertext)
    assert raw.startswith(message)
    pad_count = len(raw) - len(message)
    assert raw[len(message):] == bytes([pad_count]) * pad_count
    # And the high-level decrypt does strip it.
    assert cipher.decrypt(iv, ciphertext) == message


def test_identical_plaintext_blocks_encrypt_differently_under_chaining():
    """Two equal blocks must not produce two equal ciphertext blocks.

    This is the property the chaining exists for; a mode that XORed nothing
    into the block before AES (ECB) would fail it.
    """

    key = bytes(range(16))
    iv = bytes(16)
    cipher = CBC(key)
    block = b"\x00" * 16
    ciphertext = cipher.encrypt_blocks(iv, block + block)
    assert ciphertext[:16] != ciphertext[16:]
    assert cipher.decrypt_blocks(iv, ciphertext) == block + block


def test_decrypt_raises_padding_error_for_invalid_padding():
    """A crafted ciphertext whose plaintext has bad padding must raise PaddingError.

    With a single ciphertext block the plaintext is ``AES_decrypt(block) XOR IV``,
    so choosing the IV dictates the plaintext exactly -- no guessing involved.
    Each case builds an IV that forces a particular malformed padding.
    """

    key = bytes(range(16))
    block = bytes(range(16, 32))
    decrypted = AES(key).decrypt_block(block)
    cipher = CBC(key)

    bad_paddings = [
        bytes(15) + b"\x00",           # claims zero bytes of padding
        bytes(15) + b"\x11",           # claims 17, more than the block size
        b"\x04\x03\x04\x04" + bytes(12),  # claims 4, trailing bytes disagree
    ]
    for target in bad_paddings:
        crafted_iv = xor_bytes(decrypted, target)
        # Confirm the construction really produces that plaintext.
        assert cipher.decrypt_blocks(crafted_iv, block) == target
        with pytest.raises(PaddingError):
            cipher.decrypt(crafted_iv, block)


def test_a_valid_padding_survives_the_crafted_iv_construction():
    """The same construction with good padding decrypts cleanly, so the test above
    is proving the padding check and not merely that decrypt always raises."""

    key = bytes(range(16))
    block = bytes(range(16, 32))
    decrypted = AES(key).decrypt_block(block)
    target = b"payload!" + bytes([8]) * 8  # 8-byte message, 8 bytes of padding
    crafted_iv = xor_bytes(decrypted, target)
    assert CBC(key).decrypt(crafted_iv, block) == b"payload!"


# ---------------------------------------------------------------------------
# Differential test against the reference implementation
# ---------------------------------------------------------------------------

def test_differential_against_the_reference_implementation():
    """Several hundred random cases, compared to an independent implementation.

    The reference is the oracle: if the two disagree, one of them is wrong, and
    it is far more likely to be this one.  The seed is fixed so a failure can be
    reproduced exactly.  Every key size is exercised, the lengths include empty
    input and the bytes on either side of a block boundary, and both the padded
    API and the raw block-grid API are compared -- in both directions.
    """

    try:
        from cryptography.hazmat.primitives import padding as reference_padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        pytest.fail(
            "the differential test needs the reference implementation that "
            "requirements.txt declares: %s" % exc
        )

    rnd = random.Random(0xCBC5EED)
    # The block-boundary lengths are pinned so the sweep always covers them;
    # the rest are random, so the chaining is exercised at lengths nobody chose.
    pinned_lengths = [0, 1, 15, 16, 17, 31, 32, 33, 48, 64]
    lengths = pinned_lengths + [rnd.randrange(0, 128) for _ in range(310)]

    checked = 0
    for length in lengths:
        key = bytes(rnd.getrandbits(8) for _ in range(rnd.choice((16, 24, 32))))
        iv = bytes(rnd.getrandbits(8) for _ in range(16))
        plaintext = bytes(rnd.getrandbits(8) for _ in range(length))
        cipher = CBC(key)
        label = (len(key), length)

        # -- padded API: our encrypt against AES-CBC + PKCS#7 ---------------
        ours = cipher.encrypt(iv, plaintext)
        padder = reference_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        reference_ciphertext = encryptor.update(padded) + encryptor.finalize()
        assert ours == reference_ciphertext, label

        # -- and back: our decrypt, then the oracle's unpadding ------------
        assert cipher.decrypt(iv, ours) == plaintext, label
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        recovered_padded = decryptor.update(ours) + decryptor.finalize()
        unpadder = reference_padding.PKCS7(128).unpadder()
        reference_plaintext = unpadder.update(recovered_padded) + unpadder.finalize()
        assert reference_plaintext == plaintext, label

        # -- raw block-grid API: our blocks against AES-CBC, no padding ----
        if length % CBC_BLOCK_SIZE == 0:
            raw_encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            reference_raw = raw_encryptor.update(plaintext) + raw_encryptor.finalize()
            assert cipher.encrypt_blocks(iv, plaintext) == reference_raw, label
            assert cipher.decrypt_blocks(iv, reference_raw) == plaintext, label
            # Our own ciphertext must decrypt under the oracle as well.
            raw_decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            assert (
                raw_decryptor.update(ours) + raw_decryptor.finalize()
            ) == padded, label

        checked += 1

    assert checked == len(lengths) >= 300


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------
# Every one of these must raise ValueError -- not IndexError, not struct.error,
# not a bare assert.

def test_a_key_that_is_not_16_24_or_32_bytes_is_value_error():
    for length in (0, 1, 15, 17, 23, 25, 31, 33, 64):
        with pytest.raises(ValueError):
            CBC(bytes(length))


def test_an_iv_that_is_not_16_bytes_is_value_error():
    cipher = CBC(bytes(16))
    for length in (0, 1, 15, 17, 32):
        bad_iv = bytes(length)
        with pytest.raises(ValueError):
            cipher.encrypt(bad_iv, b"x")
        with pytest.raises(ValueError):
            cipher.decrypt(bad_iv, bytes(16))
        with pytest.raises(ValueError):
            cipher.encrypt_blocks(bad_iv, bytes(16))
        with pytest.raises(ValueError):
            cipher.decrypt_blocks(bad_iv, bytes(16))


def test_ciphertext_that_is_not_a_whole_number_of_blocks_is_value_error():
    cipher = CBC(bytes(16))
    iv = bytes(16)
    for length in (1, 15, 17, 31, 33):
        bad = bytes(length)
        with pytest.raises(ValueError):
            cipher.decrypt_blocks(iv, bad)
        with pytest.raises(ValueError):
            cipher.decrypt(iv, bad)
        # The same rule applies to the encrypt side.
        with pytest.raises(ValueError):
            cipher.encrypt_blocks(iv, bad)


@pytest.mark.parametrize("bad", ["a string", 123, None, [1, 2, 3], 3.5])
def test_non_bytes_arguments_are_value_error(bad):
    cipher = CBC(bytes(16))
    iv = bytes(16)
    with pytest.raises(ValueError):
        CBC(bad)
    with pytest.raises(ValueError):
        cipher.encrypt(bad, b"x")
    with pytest.raises(ValueError):
        cipher.encrypt(iv, bad)
    with pytest.raises(ValueError):
        cipher.decrypt(iv, bad)
    with pytest.raises(ValueError):
        cipher.encrypt_blocks(iv, bad)
    with pytest.raises(ValueError):
        cipher.decrypt_blocks(iv, bad)
    with pytest.raises(ValueError):
        pkcs7_pad(bad)
    with pytest.raises(ValueError):
        pkcs7_unpad(bad)


# ---------------------------------------------------------------------------
# Structural checks
# ---------------------------------------------------------------------------

def test_block_size_constant():
    assert CBC_BLOCK_SIZE == 16


def test_padding_error_is_a_value_error():
    """Callers that only catch ValueError must still catch bad padding."""

    assert issubclass(PaddingError, ValueError)


def test_the_iv_changes_the_first_block_and_therefore_the_whole_message():
    """A different IV must change every ciphertext block, not just the first."""

    key = bytes(range(16))
    cipher = CBC(key)
    data = bytes(range(32))
    first = cipher.encrypt_blocks(bytes(16), data)
    second = cipher.encrypt_blocks(b"\x01" + bytes(15), data)
    assert first != second
    assert first[:16] != second[:16]
    assert first[16:] != second[16:]
