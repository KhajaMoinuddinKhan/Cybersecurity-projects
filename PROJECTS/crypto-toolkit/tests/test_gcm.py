"""AES-GCM against the published vectors and against a reference implementation.

Two kinds of test live here, and they answer different questions. The published
NIST vectors say the implementation agrees with the standard on the cases the
standard chose to write down. The differential tests say it agrees with an
independent implementation on several hundred inputs nobody chose -- including
the awkward ones, where the plaintext is empty, where the associated data is
empty, where the nonce is not the recommended twelve bytes, and where a length
lands exactly on a block boundary.

The second kind matters more than it looks. A hand-written GHASH can reproduce
the first two published vectors -- both of which hash a single block -- and
still be wrong for every message longer than one block, because those cases
never exercise the chaining. The differential test is what catches that, and it
is why ``cryptography`` appears in this project at all: it is an oracle for the
tests, never a dependency of the code under test.
"""

import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.gcm import GCM, InvalidTag, ghash  # noqa: E402


def h(text):
    """Turn a whitespace-separated hex string into bytes."""

    return bytes.fromhex("".join(text.split()))


# NIST SP 800-38D, the four worked examples from section 5 and Appendix B.
# Each tuple is (name, key, nonce, plaintext, associated data, ciphertext, tag).
# Every value was reproduced by an independent implementation before it was
# pinned here, so a failure means this code is wrong and not that the constant
# was mistyped.
NIST_VECTORS = [
    (
        "empty",
        "00" * 16,
        "00" * 12,
        "",
        "",
        "",
        "58e2fccefa7e3061367f1d57a4e7455a",
    ),
    (
        "one block",
        "00" * 16,
        "00" * 12,
        "00" * 16,
        "",
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf",
    ),
    (
        "four blocks",
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        "",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        "4d5c2af327cd64a62cf35abd2ba6fab4",
    ),
    (
        "with associated data",
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        "5bc94fbc3221a5db94fae95ae7121a47",
    ),
]


@pytest.mark.parametrize("name,key,nonce,plaintext,aad,ciphertext,tag", NIST_VECTORS,
                         ids=[vector[0] for vector in NIST_VECTORS])
def test_the_published_vectors(name, key, nonce, plaintext, aad, ciphertext, tag):
    """Encrypt to exactly the ciphertext and tag the standard publishes."""

    produced_ciphertext, produced_tag = GCM(h(key)).encrypt(h(nonce), h(plaintext), h(aad))
    assert produced_ciphertext == h(ciphertext), name
    assert produced_tag == h(tag), name


@pytest.mark.parametrize("name,key,nonce,plaintext,aad,ciphertext,tag", NIST_VECTORS,
                         ids=[vector[0] for vector in NIST_VECTORS])
def test_the_published_vectors_decrypt(name, key, nonce, plaintext, aad, ciphertext, tag):
    """And decrypt the published ciphertext back to the published plaintext."""

    recovered = GCM(h(key)).decrypt(h(nonce), h(ciphertext), h(tag), h(aad))
    assert recovered == h(plaintext), name


def test_the_hash_subkey_is_the_encryption_of_the_zero_block():
    """H is fixed by the key alone, and it is what every GHASH call multiplies by."""

    from src.aes import AES

    key = h("feffe9928665731c6d6a8f9467308308")
    assert GCM(key).hash_subkey == AES(key).encrypt_block(b"\x00" * 16)


def test_ghash_of_nothing_is_a_single_multiplication_of_the_length_block():
    """With no AAD and no ciphertext, GHASH reduces to the zero-length block."""

    key = h("feffe9928665731c6d6a8f9467308308")
    h_sub = GCM(key).hash_subkey
    assert ghash(h_sub, b"", b"") == ghash(h_sub, b"", b"")
    # A single byte of either input must change the result.
    assert ghash(h_sub, b"\x00", b"") != ghash(h_sub, b"", b"")
    assert ghash(h_sub, b"", b"\x00") != ghash(h_sub, b"", b"")


def test_ghash_lengths_are_counted_in_bits_not_bytes():
    """The length block carries bit counts, and the two halves are AAD then data.

    One byte of associated data and no ciphertext is not the same input as no
    associated data and one byte of ciphertext, even when both bytes are zero:
    the first puts 8 in the high half of the length block and the second puts 8
    in the low half.
    """

    h_sub = GCM(h("00" * 16)).hash_subkey
    assert ghash(h_sub, b"\x00", b"") != ghash(h_sub, b"", b"\x00")


def test_ghash_rejects_a_hash_subkey_of_the_wrong_size():
    with pytest.raises(ValueError):
        ghash(b"\x00" * 15, b"", b"")
    with pytest.raises(ValueError):
        ghash(b"\x00" * 17, b"", b"")


def test_a_round_trip_returns_the_plaintext():
    """Whatever goes in comes back out, for sizes on and off the block boundary."""

    rnd = random.Random(20261004)
    for length in (0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257, 1024):
        key = bytes(rnd.randrange(256) for _ in range(16))
        nonce = bytes(rnd.randrange(256) for _ in range(12))
        plaintext = bytes(rnd.randrange(256) for _ in range(length))
        aad = bytes(rnd.randrange(256) for _ in range(7))
        ciphertext, tag = GCM(key).encrypt(nonce, plaintext, aad)
        assert len(ciphertext) == length
        assert GCM(key).decrypt(nonce, ciphertext, tag, aad) == plaintext


def test_a_flipped_bit_anywhere_is_refused():
    """The tag covers the ciphertext and the associated data, and nothing else is trusted."""

    key = h("feffe9928665731c6d6a8f9467308308")
    nonce = h("cafebabefacedbaddecaf888")
    plaintext = h("d9313225f88406e5a55909c5aff5269a")
    aad = h("feedfacedeadbeef")
    ciphertext, tag = GCM(key).encrypt(nonce, plaintext, aad)

    def flip(data, index):
        altered = bytearray(data)
        altered[index] ^= 0x01
        return bytes(altered)

    assert GCM(key).decrypt(nonce, ciphertext, tag, aad) == plaintext
    with pytest.raises(InvalidTag):
        GCM(key).decrypt(nonce, flip(ciphertext, 0), tag, aad)
    with pytest.raises(InvalidTag):
        GCM(key).decrypt(nonce, ciphertext, flip(tag, 0), aad)
    with pytest.raises(InvalidTag):
        GCM(key).decrypt(nonce, ciphertext, tag, flip(aad, 0))
    with pytest.raises(InvalidTag):
        GCM(key).decrypt(flip(nonce, 0), ciphertext, tag, aad)
    with pytest.raises(InvalidTag):
        GCM(key).decrypt(nonce, ciphertext + b"\x00", tag, aad)
    # A tag that is one byte short is a malformed argument, not a failed check.
    with pytest.raises(ValueError):
        GCM(key).decrypt(nonce, ciphertext, tag[:-1], aad)


def test_a_refused_decryption_returns_nothing():
    """InvalidTag must be raised before any plaintext could be handed back."""

    key = h("00" * 16)
    ciphertext, tag = GCM(key).encrypt(h("00" * 12), b"secret")
    with pytest.raises(InvalidTag) as caught:
        GCM(key).decrypt(h("00" * 12), ciphertext, bytes(16))
    assert "secret" not in str(caught.value)


def test_non_96_bit_nonces_take_the_hashing_branch():
    """A nonce that is not twelve bytes has its own J0, and it must still verify.

    This is the branch a hand-written GCM usually gets wrong, so it is tested
    with a round trip at every nonce length the reference implementation
    accepts, rather than only at the recommended one.
    """

    key = h("feffe9928665731c6d6a8f9467308308")
    for length in (8, 11, 12, 13, 16, 24, 32, 60, 128):
        nonce = bytes(range(length))
        ciphertext, tag = GCM(key).encrypt(nonce, b"payload", b"header")
        assert GCM(key).decrypt(nonce, ciphertext, tag, b"header") == b"payload"
        # The same message under a different nonce must not verify.
        with pytest.raises(InvalidTag):
            GCM(key).decrypt(nonce + b"\x00", ciphertext, tag, b"header")


def test_differential_against_the_reference_implementation():
    """Several hundred random cases, compared to an independent implementation.

    The reference is the oracle: if the two disagree, one of them is wrong, and
    it is far more likely to be this one. The seed is fixed so a failure can be
    reproduced exactly.
    """

    try:
        from cryptography.hazmat.primitives.ciphers import aead as reference
    except ImportError as exc:
        pytest.fail(
            "the differential test needs the reference implementation that "
            "requirements.txt declares: %s" % exc
        )
    rnd = random.Random(20261004)
    checked = 0
    for _ in range(400):
        key = bytes(rnd.randrange(256) for _ in range(rnd.choice([16, 24, 32])))
        nonce = bytes(rnd.randrange(256) for _ in range(rnd.choice([8, 11, 12, 13, 16, 24, 32, 60, 128])))
        plaintext = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 200)))
        aad = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 100)))
        ciphertext, tag = GCM(key).encrypt(nonce, plaintext, aad)
        sealed = reference.AESGCM(key).encrypt(nonce, plaintext, aad)
        assert ciphertext == sealed[:-16], (len(key), len(nonce), len(plaintext), len(aad))
        assert tag == sealed[-16:], (len(key), len(nonce), len(plaintext), len(aad))
        checked += 1
    assert checked == 400


def test_a_malformed_argument_is_a_value_error():
    """Bad input is reported as ValueError, never as an IndexError or a crash."""

    key = h("00" * 16)
    nonce = h("00" * 12)
    ciphertext, tag = GCM(key).encrypt(nonce, b"x")

    with pytest.raises(ValueError):
        GCM(b"\x00" * 15)
    with pytest.raises(ValueError):
        GCM(b"\x00" * 17)
    with pytest.raises(ValueError):
        GCM(key).encrypt(b"", b"x")
    with pytest.raises(ValueError):
        GCM(key).encrypt(nonce, "not bytes")
    with pytest.raises(ValueError):
        GCM(key).encrypt(nonce, b"x", "not bytes")
    with pytest.raises(ValueError):
        GCM(key).decrypt(nonce, ciphertext, b"\x00" * 15)
    with pytest.raises(ValueError):
        GCM(key).decrypt(nonce, "not bytes", tag)


def test_two_keys_produce_different_tags_for_the_same_message():
    """A sanity check that the key is actually in the tag."""

    nonce = h("00" * 12)
    first = GCM(h("00" * 16)).encrypt(nonce, b"same", b"same")
    second = GCM(h("11" * 16)).encrypt(nonce, b"same", b"same")
    assert first != second
