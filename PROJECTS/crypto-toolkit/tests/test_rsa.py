"""RSA-OAEP against the published Wycheproof corpus and a reference implementation.

Two kinds of test live here, and they answer different questions. The Wycheproof
corpus is a fixed set of ciphertexts under one published 2048-bit key: 18 of them
carry a message and must decrypt to exactly that message, and 19 of them are
malformed in a specific way and must be refused. The refused half is the point.
A decryptor that returns *something* for every input passes the 18 valid cases
and fails all 19 invalid ones, so the corpus is what distinguishes a real OAEP
decoder from a length check wearing a costume. The corpus is vendored under
``tests/vectors/`` so the suite runs with no network.

The differential tests say the implementation agrees with an independent one on
inputs nobody chose -- random keys, random message lengths from empty to the
maximum, and random labels, in both directions. That is the only way to catch an
MGF1 or a CRT recombination that happens to be right on the one published key
and wrong elsewhere.

The oracle is the same one the rest of the project uses: ``cryptography``,
imported inside a ``try``/``except ImportError`` that calls ``pytest.fail``. The
README promises the suite fails -- not skips -- when the reference is missing, so
``pytest.importorskip`` is deliberately not used.

Nothing here asserts a value this module produced. Every expected value is either
read out of the Wycheproof file or comes back from the oracle.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.rsa import (  # noqa: E402
    OAEP_HASH_LENGTH,
    RSA_PUBLIC_EXPONENT,
    DecryptionError,
    RSAPrivateKey,
    RSAPublicKey,
    decrypt,
    encrypt,
    generate_key_pair,
    mgf1,
    oaep_decode,
    oaep_encode,
    rsaep,
    rsadp,
)
from src.sha256 import sha256  # noqa: E402


# ---------------------------------------------------------------------------
# The Wycheproof corpus, read from the vendored copy.
# ---------------------------------------------------------------------------

_VECTORS = pathlib.Path(__file__).resolve().parent / "vectors" / "wycheproof_rsa_oaep_2048_sha256.json"


def _load_corpus():
    with open(_VECTORS, encoding="utf-8") as handle:
        return json.load(handle)


_CORPUS = _load_corpus()
_GROUP = _CORPUS["testGroups"][0]


def _base64url(text: str) -> bytes:
    """Decode a JWK base64url field, restoring the stripped padding."""

    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _key_pair_from_jwk(jwk):
    def number(name: str) -> int:
        return int.from_bytes(_base64url(jwk[name]), "big")

    n, e = number("n"), number("e")
    private = RSAPrivateKey(
        n, e, number("d"), number("p"), number("q"),
        number("dp"), number("dq"), number("qi"),
    )
    return RSAPublicKey(n, e), private


_WYCHEPROOF_PUBLIC, _WYCHEPROOF_PRIVATE = _key_pair_from_jwk(_GROUP["privateKeyJwk"])

_VALID = [test for test in _GROUP["tests"] if test["result"] == "valid"]
_INVALID = [test for test in _GROUP["tests"] if test["result"] == "invalid"]


def test_the_wycheproof_corpus_is_the_published_one():
    # Guard the corpus itself: a truncated download would turn 19 refusal tests
    # into a green suite that proves less than it claims.
    assert _CORPUS["numberOfTests"] == 37
    assert _GROUP["keySize"] == 2048
    assert _GROUP["sha"] == "SHA-256"
    assert _GROUP["mgfSha"] == "SHA-256"
    assert len(_VALID) == 18
    assert len(_INVALID) == 19
    assert _WYCHEPROOF_PUBLIC.size_bytes() == 256


@pytest.mark.parametrize(
    "test",
    _VALID,
    ids=["tcId%d" % test["tcId"] for test in _VALID],
)
def test_a_valid_wycheproof_ciphertext_decrypts_to_the_message(test):
    # The label is part of the OAEP input, so a case encrypted with a label is
    # only recoverable with that label; the corpus encodes it as hex.
    label = bytes.fromhex(test.get("label", ""))
    recovered = decrypt(_WYCHEPROOF_PRIVATE, bytes.fromhex(test["ct"]), label)
    assert recovered == bytes.fromhex(test["msg"])


@pytest.mark.parametrize(
    "test",
    _INVALID,
    ids=["tcId%d" % test["tcId"] for test in _INVALID],
)
def test_an_invalid_wycheproof_ciphertext_is_refused(test):
    label = bytes.fromhex(test.get("label", ""))
    with pytest.raises(DecryptionError):
        decrypt(_WYCHEPROOF_PRIVATE, bytes.fromhex(test["ct"]), label)


def test_a_valid_wycheproof_message_re_encrypts_and_decrypts():
    # The ciphertexts are randomised, so the corpus cannot be checked by
    # re-encrypting; but the recovered message must survive a round trip under
    # the same key and label.
    for test in _VALID:
        label = bytes.fromhex(test.get("label", ""))
        message = bytes.fromhex(test["msg"])
        ciphertext = encrypt(_WYCHEPROOF_PUBLIC, message, label)
        assert len(ciphertext) == 256
        assert decrypt(_WYCHEPROOF_PRIVATE, ciphertext, label) == message


# ---------------------------------------------------------------------------
# The mask generation function.
# ---------------------------------------------------------------------------


def test_mgf1_matches_the_counter_mode_construction():
    # An independent oracle for MGF1: hashlib, not this project's SHA-256. The
    # mask is SHA-256(seed || counter) for a 32-bit big-endian counter.
    seed = b"a seed for the mask"
    length = 100
    expected = b"".join(
        hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        for counter in range(4)
    )[:length]
    assert mgf1(seed, length) == expected


def test_mgf1_is_deterministic_and_truncates_exactly():
    assert mgf1(b"seed", 0) == b""
    assert mgf1(b"seed", 32) == mgf1(b"seed", 32)
    for length in (1, 31, 32, 33, 64, 65, 200):
        assert len(mgf1(b"seed", length)) == length
    # A longer request is the shorter one extended, block by block.
    assert mgf1(b"seed", 65)[:64] == mgf1(b"seed", 64)


def test_mgf1_rejects_a_negative_length():
    with pytest.raises(ValueError):
        mgf1(b"seed", -1)


# ---------------------------------------------------------------------------
# The OAEP block, on its own.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [0, 1, 31, 32, 33, 100, 190])
def test_oaep_round_trips_a_message_of_every_length(length):
    k = 256
    message = bytes(range(256))[:length]
    encoded = oaep_encode(message, k)
    assert len(encoded) == k
    assert encoded[0] == 0x00
    assert oaep_decode(encoded, k) == message


def test_oaep_is_randomised():
    # Two encodings of one message must differ, or the seed is not being drawn.
    first = oaep_encode(b"the same message", 256)
    second = oaep_encode(b"the same message", 256)
    assert first != second


def test_oaep_round_trips_with_a_label():
    k = 256
    label = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    encoded = oaep_encode(b"labelled", k, label)
    assert oaep_decode(encoded, k, label) == b"labelled"
    with pytest.raises(DecryptionError):
        oaep_decode(encoded, k, b"another label")


def test_oaep_encode_refuses_a_message_that_is_too_long():
    k = 256
    maximum = k - 2 * OAEP_HASH_LENGTH - 2
    oaep_encode(b"x" * maximum, k)  # exactly the maximum is accepted
    with pytest.raises(ValueError):
        oaep_encode(b"x" * (maximum + 1), k)


def _mask_db(db: bytes, k: int, seed: bytes = b"\x00" * OAEP_HASH_LENGTH) -> bytes:
    """Wrap a chosen DB in the two OAEP masks, to build blocks by hand."""

    masked_db = bytes(a ^ b for a, b in zip(db, mgf1(seed, k - OAEP_HASH_LENGTH - 1), strict=True))
    masked_seed = bytes(a ^ b for a, b in zip(seed, mgf1(masked_db, OAEP_HASH_LENGTH), strict=True))
    return b"\x00" + masked_seed + masked_db


def test_oaep_decode_refuses_blocks_that_do_not_decode():
    k = 256
    label = b""
    encoded = oaep_encode(b"the message", k, label)

    # A leading byte that is not zero.
    with pytest.raises(DecryptionError):
        oaep_decode(b"\x01" + encoded[1:], k, label)

    # A flipped bit in the masked seed corrupts the seed, and so the whole DB.
    damaged = bytearray(encoded)
    damaged[1] ^= 0x01
    with pytest.raises(DecryptionError):
        oaep_decode(bytes(damaged), k, label)

    # A label that does not match the one used to encode.
    with pytest.raises(DecryptionError):
        oaep_decode(encoded, k, b"a different label")

    lhash = sha256(label)

    # A DB whose padding is all zero: there is no 0x01 separator at all.
    db = lhash + b"\x00" * (k - 2 * OAEP_HASH_LENGTH - 1)
    with pytest.raises(DecryptionError):
        oaep_decode(_mask_db(db, k), k, label)

    # A DB whose separator byte is 0xff rather than 0x01.
    db = lhash + b"\x00" * (k - 2 * OAEP_HASH_LENGTH - 2) + b"\xff"
    with pytest.raises(DecryptionError):
        oaep_decode(_mask_db(db, k), k, label)

    # A DB whose label hash is wrong.
    db = b"\x00" * OAEP_HASH_LENGTH + b"\x00" * (k - 2 * OAEP_HASH_LENGTH - 2) + b"\x01"
    with pytest.raises(DecryptionError):
        oaep_decode(_mask_db(db, k), k, label)


def test_oaep_decode_refuses_a_block_of_the_wrong_length():
    for wrong in (b"", b"\x00" * 255, b"\x00" * 257):
        with pytest.raises(DecryptionError):
            oaep_decode(wrong, 256)


# ---------------------------------------------------------------------------
# The RSA primitives.
# ---------------------------------------------------------------------------


def test_rsaep_and_rsadp_are_inverses():
    public, private = generate_key_pair(1024)
    for representative in (0, 1, 2, 12345, public.n - 1):
        ciphertext = rsaep(public, representative)
        assert rsadp(private, ciphertext) == representative


def test_rsaep_rejects_a_representative_out_of_range():
    public, _ = generate_key_pair(512)
    with pytest.raises(ValueError):
        rsaep(public, public.n)
    with pytest.raises(ValueError):
        rsaep(public, -1)


def test_rsadp_refuses_a_representative_out_of_range():
    _, private = generate_key_pair(512)
    with pytest.raises(DecryptionError):
        rsadp(private, private.n)
    with pytest.raises(DecryptionError):
        rsadp(private, -1)


def test_a_fault_in_the_crt_path_is_refused_not_returned():
    # Flip one bit of dp. The two half-exponentiations no longer agree, so the
    # recombination produces a wrong representative; the re-encryption check is
    # what turns that into a refusal instead of a plausible-looking plaintext.
    public, private = generate_key_pair(1024)
    ciphertext = encrypt(public, b"a faulted decryption")
    faulty = RSAPrivateKey(
        private.n, private.e, private.d, private.p, private.q,
        private.dp ^ 1, private.dq, private.qinv,
    )
    with pytest.raises(DecryptionError):
        decrypt(faulty, ciphertext)


# ---------------------------------------------------------------------------
# encrypt and decrypt.
# ---------------------------------------------------------------------------


def test_encrypt_produces_the_modulus_length():
    public, _ = generate_key_pair(1024)
    maximum = public.size_bytes() - 2 * OAEP_HASH_LENGTH - 2
    for length in (0, 1, 32, maximum):
        ciphertext = encrypt(public, b"x" * length)
        assert len(ciphertext) == public.size_bytes() == 128


def test_encrypt_refuses_a_message_that_is_too_long():
    public, _ = generate_key_pair(1024)
    maximum = public.size_bytes() - 2 * OAEP_HASH_LENGTH - 2
    encrypt(public, b"x" * maximum)  # exactly the maximum is accepted
    with pytest.raises(ValueError):
        encrypt(public, b"x" * (maximum + 1))


def test_decrypt_refuses_a_ciphertext_of_the_wrong_length():
    _, private = generate_key_pair(1024)
    for wrong in (b"", b"\x00" * 127, b"\x00" * 129):
        with pytest.raises(DecryptionError):
            decrypt(private, wrong)


def test_decrypt_refuses_a_representative_at_or_above_the_modulus():
    _, private = generate_key_pair(1024)
    k = (private.n.bit_length() + 7) // 8
    with pytest.raises(DecryptionError):
        decrypt(private, private.n.to_bytes(k, "big"))
    with pytest.raises(DecryptionError):
        decrypt(private, (private.n + 1).to_bytes(k, "big"))


def test_decrypt_refuses_a_corrupted_ciphertext():
    public, private = generate_key_pair(1024)
    ciphertext = encrypt(public, b"a message that must survive intact")
    damaged = bytearray(ciphertext)
    damaged[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt(private, bytes(damaged))


def test_decrypt_refuses_the_wrong_label():
    public, private = generate_key_pair(1024)
    ciphertext = encrypt(public, b"labelled", b"the label")
    assert decrypt(private, ciphertext, b"the label") == b"labelled"
    with pytest.raises(DecryptionError):
        decrypt(private, ciphertext, b"the wrong label")


# ---------------------------------------------------------------------------
# Key generation.
# ---------------------------------------------------------------------------


def test_generate_key_pair_rejects_a_bad_bit_length():
    for bad in (0, 8, 256, 511, 513, 1024 + 1, -512):
        with pytest.raises(ValueError):
            generate_key_pair(bad)
    with pytest.raises(ValueError):
        generate_key_pair(True)
    with pytest.raises(ValueError):
        generate_key_pair(1024.0)


@pytest.mark.parametrize("bits", [512, 1024, 2048])
def test_a_generated_key_has_the_expected_structure(bits):
    public, private = generate_key_pair(bits)
    assert public.n.bit_length() == bits
    assert public.size_bytes() == bits // 8
    assert public.e == RSA_PUBLIC_EXPONENT
    assert private.n == public.n and private.e == public.e
    # n is the product of the two primes, and the CRT parameters are the
    # reductions and the inverse the reconstruction needs.
    assert private.n == private.p * private.q
    assert private.p != private.q
    assert private.dp == private.d % (private.p - 1)
    assert private.dq == private.d % (private.q - 1)
    assert private.qinv * private.q % private.p == 1
    # d is the inverse of e modulo the Carmichael function, so it inverts e on
    # any message: e*d == 1 mod lcm(p-1, q-1).
    from math import gcd

    assert private.e * private.d % ((private.p - 1) * (private.q - 1) // gcd(private.p - 1, private.q - 1)) == 1


@pytest.mark.parametrize("bits", [512, 1024, 2048])
def test_a_generated_key_round_trips(bits):
    public, private = generate_key_pair(bits)
    if bits < 1024:
        # A modulus below 2*32 + 2 bytes cannot carry OAEP at all, which the
        # encrypt length check enforces.
        with pytest.raises(ValueError):
            encrypt(public, b"")
        return
    maximum = public.size_bytes() - 2 * OAEP_HASH_LENGTH - 2
    for message in (b"", b"one", b"a longer message for the round trip", b"x" * maximum):
        ciphertext = encrypt(public, message)
        assert decrypt(private, ciphertext) == message


def test_two_generated_keys_differ():
    first, _ = generate_key_pair(512)
    second, _ = generate_key_pair(512)
    assert first.n != second.n


# ---------------------------------------------------------------------------
# Differential comparison against the reference implementation.
# ---------------------------------------------------------------------------

_DIFFERENTIAL_SEED = 0xA0E1A0E1


def _load_oracle():
    """Import ``cryptography`` or fail the test, never skip it."""

    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError as exc:
        pytest.fail(
            "the differential test needs the reference implementation that "
            "requirements.txt declares: %s" % exc
        )
    return {"rsa": rsa, "padding": padding, "hashes": hashes}


def _oaep(padding, hashes, label: bytes):
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=label,
    )


def test_differential_against_the_reference_implementation():
    """Compare 300 random cases against an independent implementation.

    Both directions are checked for each case. Every ciphertext this module
    produces must be decrypted to the same message by the oracle, and every
    ciphertext the oracle produces must be decrypted to the same message here.
    Message lengths run from empty to the maximum the modulus allows, and the
    label is a fresh random byte string each time. The keys are the oracle's own
    for 1024 and 2048 bits; a 512-bit key is below the OAEP floor, so that size
    is checked only for the shared refusal. The seed is fixed so a failure
    reproduces exactly.
    """

    oracle = _load_oracle()
    rsa = oracle["rsa"]
    padding = oracle["padding"]
    hashes = oracle["hashes"]

    rng = random.Random(_DIFFERENTIAL_SEED)
    checked = 0

    # A 512-bit modulus is 64 bytes, and OAEP with SHA-256 needs 2*32 + 2 = 66,
    # so no message -- not even the empty one -- fits. The reference refuses it,
    # and so must we. The oracle cannot generate a key this small, so the pair
    # is this module's own.
    public_512, _ = generate_key_pair(512)
    reference_public_512 = rsa.RSAPublicNumbers(public_512.e, public_512.n).public_key()
    empty_oaep = _oaep(padding, hashes, b"")
    with pytest.raises(ValueError):
        encrypt(public_512, b"")
    with pytest.raises(ValueError):
        reference_public_512.encrypt(b"", empty_oaep)

    for size in (1024, 2048):
        for _ in range(3):
            reference_private = rsa.generate_private_key(
                public_exponent=RSA_PUBLIC_EXPONENT, key_size=size
            )
            numbers = reference_private.private_numbers()
            public_numbers = numbers.public_numbers
            public_key = RSAPublicKey(public_numbers.n, public_numbers.e)
            private_key = RSAPrivateKey(
                public_numbers.n, public_numbers.e, numbers.d,
                numbers.p, numbers.q, numbers.dmp1, numbers.dmq1, numbers.iqmp,
            )
            k = public_key.size_bytes()
            maximum = k - 2 * OAEP_HASH_LENGTH - 2
            assert maximum > 0
            for _ in range(50):
                length = rng.randrange(0, maximum + 1)
                message = rng.randbytes(length)
                label = rng.randbytes(rng.randrange(0, 40))
                oaep = _oaep(padding, hashes, label)

                ciphertext = encrypt(public_key, message, label)
                assert len(ciphertext) == k
                assert reference_private.decrypt(ciphertext, oaep) == message

                reference_ciphertext = reference_private.public_key().encrypt(message, oaep)
                assert decrypt(private_key, reference_ciphertext, label) == message
                checked += 1

    assert checked == 300


def test_a_generated_key_interoperates_with_the_reference_implementation():
    # Key generation is this module's; prove the pair it produces is a real RSA
    # key by handing it to the oracle and exchanging messages both ways.
    oracle = _load_oracle()
    rsa = oracle["rsa"]
    public, private = generate_key_pair(1024)
    public_numbers = rsa.RSAPublicNumbers(public.e, public.n)
    reference_private = rsa.RSAPrivateNumbers(
        private.p, private.q, private.d, private.dp, private.dq, private.qinv,
        public_numbers,
    ).private_key()

    label = b"a generated key"
    oaep = _oaep(oracle["padding"], oracle["hashes"], label)
    message = b"a message under a key this module generated"

    ciphertext = encrypt(public, message, label)
    assert reference_private.decrypt(ciphertext, oaep) == message

    reference_ciphertext = reference_private.public_key().encrypt(message, oaep)
    assert decrypt(private, reference_ciphertext, label) == message
