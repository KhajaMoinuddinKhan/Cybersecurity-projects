"""The ECDSA nonce-reuse attack.

The attack is checked by recovering the private key and comparing it to the key
that signed -- and then by using the recovered key to sign something the real
verifier accepts under the real public key, which is the stronger statement: the
recovered scalar is not merely equal to the secret, it behaves like it.

Keys, digests and nonces are generated at run time.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.attacks.nonce_reuse_ecdsa import recover_nonce, recover_private_key  # noqa: E402
from src.ecdsa import (  # noqa: E402
    P256_N,
    PrivateKey,
    generate_private_key,
    sign,
    sign_deterministic,
    verify,
)
from src.sha256 import sha256  # noqa: E402


@pytest.mark.parametrize("trial", range(6))
def test_the_private_key_is_recovered_from_a_repeated_nonce(trial):
    """Two signatures that share a nonce give up the key."""

    key = generate_private_key(os.urandom(32))
    nonce = int.from_bytes(os.urandom(32), "big") % (P256_N - 1) + 1
    digest1 = sha256(os.urandom(40))
    digest2 = sha256(os.urandom(40))

    signature1 = sign(key, digest1, nonce)
    signature2 = sign(key, digest2, nonce)
    assert signature1[0] == signature2[0], "one nonce means one r"

    recovered = recover_private_key(digest1, signature1, digest2, signature2)

    assert recovered == key.secret


def test_the_nonce_itself_is_recovered():
    key = generate_private_key(os.urandom(32))
    nonce = int.from_bytes(os.urandom(32), "big") % (P256_N - 1) + 1
    digest1 = sha256(b"first message")
    digest2 = sha256(b"second message")
    signature1 = sign(key, digest1, nonce)
    signature2 = sign(key, digest2, nonce)

    assert recover_nonce(digest1, signature1, digest2, signature2) == nonce


def test_the_recovered_key_signs_signatures_the_real_verifier_accepts():
    """The stronger check: the recovered scalar behaves like the private key."""

    key = generate_private_key(os.urandom(32))
    nonce = int.from_bytes(os.urandom(32), "big") % (P256_N - 1) + 1
    digest1 = sha256(os.urandom(20))
    digest2 = sha256(os.urandom(20))
    signature1 = sign(key, digest1, nonce)
    signature2 = sign(key, digest2, nonce)

    recovered = PrivateKey(recover_private_key(digest1, signature1, digest2, signature2))

    assert recovered.public_key.x == key.public_key.x
    assert recovered.public_key.y == key.public_key.y
    fresh = sha256(b"a message the attacker chose")
    forged = sign(recovered, fresh, int.from_bytes(os.urandom(32), "big") % (P256_N - 1) + 1)
    assert verify(key.public_key, fresh, forged) is True


def test_distinct_nonces_leave_nothing_to_recover():
    """The control: the attack needs the same r, and different nonces give different r."""

    key = generate_private_key(os.urandom(32))
    digest1 = sha256(os.urandom(20))
    digest2 = sha256(os.urandom(20))
    signature1 = sign(key, digest1, int.from_bytes(os.urandom(32), "big") % (P256_N - 1) + 1)
    signature2 = sign(key, digest2, int.from_bytes(os.urandom(32), "big") % (P256_N - 1) + 1)

    if signature1[0] == signature2[0]:
        pytest.skip("two random nonces collided, which is itself remarkable")
    with pytest.raises(ValueError):
        recover_private_key(digest1, signature1, digest2, signature2)


def test_deterministic_signing_never_repeats_a_nonce():
    """The fix, demonstrated: RFC 6979 gives a different r for every message.

    This is what makes the attack above impossible to mount against a correct
    implementation, so it is worth testing rather than asserting.
    """

    key = generate_private_key(os.urandom(32))
    seen = set()
    for _ in range(60):
        digest = sha256(os.urandom(24))
        signature = sign_deterministic(key, digest)
        assert signature[0] not in seen, "RFC 6979 repeated an r"
        seen.add(signature[0])
        assert verify(key.public_key, digest, signature) is True


def test_the_same_message_signed_deterministically_twice_is_the_same_signature():
    key = generate_private_key(os.urandom(32))
    digest = sha256(b"repeatable")
    assert sign_deterministic(key, digest) == sign_deterministic(key, digest)


def test_identical_signatures_are_refused():
    key = generate_private_key(os.urandom(32))
    nonce = int.from_bytes(os.urandom(32), "big") % (P256_N - 1) + 1
    digest = sha256(b"once")
    signature = sign(key, digest, nonce)

    with pytest.raises(ValueError):
        recover_private_key(digest, signature, digest, signature)


def test_malformed_input_is_refused():
    key = generate_private_key(os.urandom(32))
    digest1 = sha256(b"a")
    digest2 = sha256(b"b")
    nonce = int.from_bytes(os.urandom(32), "big") % (P256_N - 1) + 1
    signature1 = sign(key, digest1, nonce)
    signature2 = sign(key, digest2, nonce)

    with pytest.raises(ValueError):
        recover_private_key(digest1, (0, signature1[1]), digest2, signature2)
    with pytest.raises(ValueError):
        recover_nonce("not bytes", signature1, digest2, signature2)
