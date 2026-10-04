"""ECDSA over P-256 against the published vectors and a reference implementation.

Two kinds of test live here, and they answer different questions. The published
RFC 6979 vectors say the implementation agrees with the standard on the cases
the standard chose to write down -- including the exact nonce, which is what
ties this module's explicit-nonce path to the algorithm rather than to a
plausible-looking signature of its own. The differential tests say it agrees
with an independent implementation on inputs nobody chose, which is the only
way to catch a scalar multiplication that happens to be right on the two
published messages and wrong elsewhere.

The oracle is the same one the rest of the project uses: ``cryptography``,
imported inside a ``try``/``except ImportError`` that calls ``pytest.fail``.
The README promises the suite fails -- not skips -- when the reference is
missing, so ``pytest.importorskip`` is deliberately not used.

Nothing here asserts a value this module produced. Every expected value is
either read out of RFC 6979 or comes back from the oracle.
"""

from __future__ import annotations

import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ecdsa import (  # noqa: E402
    P256_A,
    P256_B,
    P256_G,
    P256_N,
    P256_P,
    PrivateKey,
    PublicKey,
    generate_private_key,
    sign,
    sign_deterministic,
    verify,
    _is_on_curve,
    _point_add,
    _rfc6979_nonce,
    _scalar_mult,
)
from src.sha256 import sha256  # noqa: E402


# ---------------------------------------------------------------------------
# RFC 6979 appendix A.2.5, curve NIST P-256, hash SHA-256. Read out of the RFC
# text; each tuple is (nonce k, r, s) for the ASCII message.
# ---------------------------------------------------------------------------

RFC6979_PRIVATE = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
RFC6979_UX = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
RFC6979_UY = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299

RFC6979_VECTORS = [
    (
        b"sample",
        0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60,
        0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
        0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8,
    ),
    (
        b"test",
        0xD16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0,
        0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
        0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083,
    ),
]


def test_the_p256_parameters_are_the_published_ones():
    # P-256 as published in NIST SP 800-186 / SEC 2 (secp256r1) / ANSI X9.62
    # (prime256v1). If a digit here is wrong the vectors below will fail, but
    # the failure is easier to read if the constants are checked directly.
    assert P256_P == 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    assert P256_A == P256_P - 3
    assert P256_A == 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    assert P256_B == 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    assert P256_G == (
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    )
    assert P256_N == 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def test_the_base_point_is_on_the_curve():
    # y^2 == x^3 + a*x + b, the equation that makes (x, y) a point at all.
    gx, gy = P256_G
    assert (gy * gy - (gx * gx * gx + P256_A * gx + P256_B)) % P256_P == 0
    assert _is_on_curve(P256_G) is True
    # A point that does not satisfy the equation must be rejected.
    assert _is_on_curve((gx, (gy + 1) % P256_P)) is False


def test_the_order_times_the_base_point_is_the_point_at_infinity():
    # n is the order of G, so n*G is the identity by definition. This is the
    # check that the group arithmetic and the order constant agree, and it is
    # the case that exercises the infinity handling in double-and-add.
    assert _scalar_mult(P256_N, P256_G) is None
    # The neighbouring scalars must not collapse to infinity.
    assert _scalar_mult(1, P256_G) == P256_G
    assert _scalar_mult(2, P256_G) == _point_add(P256_G, P256_G)
    assert _scalar_mult(P256_N - 1, P256_G) == (
        P256_G[0],
        (-P256_G[1]) % P256_P,
    )


def test_the_published_private_key_gives_the_published_public_key():
    public = PrivateKey(RFC6979_PRIVATE).public_key
    assert public.x == RFC6979_UX
    assert public.y == RFC6979_UY
    assert _is_on_curve((RFC6979_UX, RFC6979_UY)) is True


def test_the_uncompressed_point_encoding():
    public = PrivateKey(RFC6979_PRIVATE).public_key
    encoded = public.to_bytes()
    assert len(encoded) == 65
    assert encoded[0] == 0x04
    assert encoded[1:33] == RFC6979_UX.to_bytes(32, "big")
    assert encoded[33:65] == RFC6979_UY.to_bytes(32, "big")


@pytest.mark.parametrize("message, nonce, r, s", RFC6979_VECTORS,
                         ids=[vector[0].decode() for vector in RFC6979_VECTORS])
def test_sign_with_the_published_nonce_matches_the_published_signature(message, nonce, r, s):
    # The digest is SHA-256 of the ASCII message, as the RFC specifies.
    digest = sha256(message)
    assert sign(PrivateKey(RFC6979_PRIVATE), digest, nonce) == (r, s)


@pytest.mark.parametrize("message, nonce, r, s", RFC6979_VECTORS,
                         ids=[vector[0].decode() for vector in RFC6979_VECTORS])
def test_sign_deterministic_reproduces_the_published_signature_and_nonce(message, nonce, r, s):
    # sign_deterministic must produce the published (r, s) *and* must have used
    # the published k. The nonce is not returned, so it is recovered from the
    # signature equation: k = s^-1 * (z + r*d) mod n, and compared to the RFC.
    private = PrivateKey(RFC6979_PRIVATE)
    digest = sha256(message)

    assert sign_deterministic(private, digest) == (r, s)

    z = int.from_bytes(digest, "big")
    recovered = (z + r * RFC6979_PRIVATE) * pow(s, -1, P256_N) % P256_N
    assert recovered == nonce

    # And the internal generator agrees with the RFC nonce directly.
    assert _rfc6979_nonce(private, digest) == nonce


@pytest.mark.parametrize("message, nonce, r, s", RFC6979_VECTORS,
                         ids=[vector[0].decode() for vector in RFC6979_VECTORS])
def test_the_published_signature_verifies(message, nonce, r, s):
    public = PrivateKey(RFC6979_PRIVATE).public_key
    assert verify(public, sha256(message), (r, s)) is True


def test_deterministic_signing_is_stable():
    # The same key and message must give the same signature every time: that is
    # the entire point of RFC 6979.
    private = PrivateKey(RFC6979_PRIVATE)
    digest = sha256(b"a message signed twice")
    first = sign_deterministic(private, digest)
    second = sign_deterministic(private, digest)
    assert first == second
    assert verify(private.public_key, digest, first) is True


def test_sign_honours_the_nonce_it_is_given():
    # The explicit-nonce contract: two calls with the same nonce and the same
    # key share r, which is exactly the mistake the nonce-reuse attack exploits.
    # A signer that ignored the argument could not exhibit it.
    private = PrivateKey(RFC6979_PRIVATE)
    first = sign(private, sha256(b"one"), 0x1234567890ABCDEF)
    second = sign(private, sha256(b"two"), 0x1234567890ABCDEF)
    assert first[0] == second[0]
    assert first[1] != second[1]


# ---------------------------------------------------------------------------
# Differential comparison against the reference implementation.
# ---------------------------------------------------------------------------

_RANDOM_SEED = 0xECD5A2026


def _load_oracle():
    """Import ``cryptography`` or fail the test, never skip it."""

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.hazmat.primitives.asymmetric.utils import (
            Prehashed,
            decode_dss_signature,
            encode_dss_signature,
        )
    except ImportError as exc:
        pytest.fail(
            "the differential test needs the reference implementation that "
            "requirements.txt declares: %s" % exc
        )
    return {
        "ec": ec,
        "utils": utils,
        "hashes": hashes,
        "Prehashed": Prehashed,
        "decode_dss_signature": decode_dss_signature,
        "encode_dss_signature": encode_dss_signature,
        "InvalidSignature": InvalidSignature,
    }


def test_differential_against_the_reference_implementation():
    """Sign and verify 250 random cases against an independent implementation.

    Both directions are checked. Every signature this module produces must be
    accepted by the oracle under the same public key, and every signature the
    oracle produces with its own random nonce must be accepted by this module's
    ``verify``. The seed is fixed so a failure reproduces exactly.
    """

    oracle = _load_oracle()
    ec = oracle["ec"]
    hashes = oracle["hashes"]
    Prehashed = oracle["Prehashed"]
    encode_dss_signature = oracle["encode_dss_signature"]
    decode_dss_signature = oracle["decode_dss_signature"]
    # InvalidSignature is raised by the oracle's verify on a bad signature; a
    # test that lets it escape is a failure, which is what we want.

    rng = random.Random(_RANDOM_SEED)
    checked = 0
    for _ in range(250):
        secret = rng.randrange(1, P256_N)
        nonce = rng.randrange(1, P256_N)
        digest = rng.randbytes(32)

        private = PrivateKey(secret)
        public = private.public_key

        reference_private = ec.derive_private_key(secret, ec.SECP256R1())
        reference_public = reference_private.public_key()

        # The two public keys must be the same point, or nothing else lines up.
        numbers = reference_public.public_numbers()
        assert (numbers.x, numbers.y) == (public.x, public.y)

        # Our signature, with our chosen nonce, must verify under the oracle.
        r, s = sign(private, digest, nonce)
        encoded = encode_dss_signature(r, s)
        reference_public.verify(
            encoded, digest, ec.ECDSA(Prehashed(hashes.SHA256()))
        )

        # The oracle's signature, with its own nonce, must verify under ours.
        reference_signature = reference_private.sign(
            digest, ec.ECDSA(Prehashed(hashes.SHA256()))
        )
        reference_r, reference_s = decode_dss_signature(reference_signature)
        assert verify(public, digest, (reference_r, reference_s)) is True

        checked += 1
    assert checked == 250


# ---------------------------------------------------------------------------
# Rejection behaviour.
# ---------------------------------------------------------------------------


def _reference_signature():
    private = PrivateKey(RFC6979_PRIVATE)
    digest = sha256(b"sample")
    return private, digest, sign(private, digest, RFC6979_VECTORS[0][1])


def test_verify_rejects_a_tampered_digest():
    private, digest, signature = _reference_signature()
    tampered = bytes([digest[0] ^ 0x01]) + digest[1:]
    assert verify(private.public_key, digest, signature) is True
    assert verify(private.public_key, tampered, signature) is False


def test_verify_rejects_a_tampered_r():
    private, digest, (r, s) = _reference_signature()
    assert verify(private.public_key, digest, ((r + 1) % P256_N, s)) is False


def test_verify_rejects_a_tampered_s():
    private, digest, (r, s) = _reference_signature()
    assert verify(private.public_key, digest, (r, (s + 1) % P256_N)) is False


def test_verify_rejects_values_out_of_range():
    private, digest, (r, s) = _reference_signature()
    for out_of_range in (0, P256_N, P256_N + 1, -1):
        assert verify(private.public_key, digest, (out_of_range, s)) is False
        assert verify(private.public_key, digest, (r, out_of_range)) is False


def test_verify_rejects_a_signature_from_another_key():
    first = PrivateKey(RFC6979_PRIVATE)
    second = PrivateKey(0x1111111111111111111111111111111111111111111111111111111111111111)
    digest = sha256(b"sample")
    signature = sign(first, digest, RFC6979_VECTORS[0][1])
    assert verify(first.public_key, digest, signature) is True
    assert verify(second.public_key, digest, signature) is False


def test_sign_rejects_a_nonce_outside_the_valid_range():
    private = PrivateKey(RFC6979_PRIVATE)
    digest = sha256(b"sample")
    for bad in (0, P256_N, P256_N + 1, -1, -(P256_N - 1)):
        with pytest.raises(ValueError):
            sign(private, digest, bad)


def test_sign_rejects_a_digest_that_is_not_bytes():
    private = PrivateKey(RFC6979_PRIVATE)
    for bad in ("a string", 12345, None, [1, 2, 3], object()):
        with pytest.raises(ValueError):
            sign(private, bad, 1)


def test_verify_rejects_a_malformed_argument_as_a_value_error():
    private = PrivateKey(RFC6979_PRIVATE)
    digest = sha256(b"sample")
    signature = sign(private, digest, RFC6979_VECTORS[0][1])
    with pytest.raises(ValueError):
        verify(private.public_key, "not bytes", signature)
    with pytest.raises(ValueError):
        verify(private.public_key, digest, signature[0])


def test_a_public_key_must_be_on_the_curve():
    gx, gy = P256_G
    PublicKey((gx, gy))  # a real point is accepted
    with pytest.raises(ValueError):
        PublicKey((gx, (gy + 1) % P256_P))
    with pytest.raises(ValueError):
        PublicKey((P256_P, gy))
    with pytest.raises(ValueError):
        PublicKey((gx,))


def test_a_private_key_must_be_in_range():
    PrivateKey(1)
    PrivateKey(P256_N - 1)
    for bad in (0, P256_N, P256_N + 1, -1):
        with pytest.raises(ValueError):
            PrivateKey(bad)


# ---------------------------------------------------------------------------
# Deterministic key derivation.
# ---------------------------------------------------------------------------


def test_generate_private_key_is_deterministic():
    first = generate_private_key(b"a repeatable seed")
    second = generate_private_key(b"a repeatable seed")
    assert first.secret == second.secret
    assert first.public_key.x == second.public_key.x
    assert first.public_key.y == second.public_key.y


def test_generate_private_key_differs_for_different_seeds():
    seeds = [b"", b"a", b"b", b"seed one", b"seed two", bytes(range(32))]
    secrets = [generate_private_key(seed).secret for seed in seeds]
    assert len(set(secrets)) == len(secrets)


def test_generate_private_key_matches_the_documented_derivation():
    # INTERFACES.md fixes the derivation: sha256(seed) mod (n - 1) + 1.
    for seed in (b"", b"seed", b"another seed", bytes(range(50))):
        expected = int.from_bytes(sha256(seed), "big") % (P256_N - 1) + 1
        derived = generate_private_key(seed)
        assert derived.secret == expected
        assert 1 <= derived.secret < P256_N
