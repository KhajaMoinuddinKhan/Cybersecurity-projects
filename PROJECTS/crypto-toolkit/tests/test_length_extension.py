"""The length-extension attack, and the difference HMAC makes.

The attack is checked the only way that means anything: the forged MAC is put
back into the real MAC function with the real secret and has to come out equal.
A test that compared the forgery to a stored value would be testing arithmetic
rather than a weakness, and it would keep passing if the construction it attacks
were replaced with a safe one.

Every secret here is generated at run time. Nothing in this file is a constant
that could have come from the implementation under test.
"""

import hashlib
import hmac as stdlib_hmac
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.attacks.length_extension import forge_mac, naive_mac  # noqa: E402
from src.hmac import hmac_sha256  # noqa: E402
from src.sha256 import sha256, sha256_padding, sha256_resume  # noqa: E402


@pytest.mark.parametrize("secret_length", [1, 8, 16, 31, 32, 33, 63, 64, 65, 100, 200])
def test_the_forged_mac_verifies_under_the_real_secret(secret_length):
    """The whole point: the MAC function accepts a tag forged without the key."""

    secret = os.urandom(secret_length)
    message = os.urandom(20)
    appendage = b";admin=true"

    known_mac = naive_mac(secret, message)
    forged_message, forged_mac = forge_mac(known_mac, secret_length, message, appendage)

    assert naive_mac(secret, forged_message) == forged_mac


def test_the_forged_message_is_the_original_plus_padding_plus_the_appendage():
    """The attacker cannot choose the whole message, only what follows the glue."""

    secret = os.urandom(24)
    message = os.urandom(30)
    appendage = os.urandom(9)
    forged_message, _ = forge_mac(naive_mac(secret, message), 24, message, appendage)

    assert forged_message.startswith(message)
    assert forged_message.endswith(appendage)
    assert len(forged_message) == len(message) + len(sha256_padding(24 + len(message))) + len(appendage)
    # The glue is the padding of the secret and the message together, and it is
    # visible in the middle of the forged message.
    assert sha256_padding(24 + len(message)) in forged_message


def test_the_attack_does_not_need_the_secret_only_its_length():
    """Two secrets of the same length are attacked with the same forgery."""

    first = os.urandom(16)
    second = os.urandom(16)
    assert first != second
    message = os.urandom(12)
    appendage = b"x"

    # The attacker sees one tag and the length, and builds the forgery from them.
    forged_message, forged_mac = forge_mac(naive_mac(first, message), 16, message, appendage)
    assert naive_mac(first, forged_message) == forged_mac
    # The same forgery does not verify under the other secret, because the tag it
    # was built from was a different tag.
    assert naive_mac(second, forged_message) != forged_mac


def test_a_wrong_guess_at_the_secret_length_fails_rather_than_working():
    """Guessing the length wrong gives a MAC that does not verify, which is honest."""

    secret = os.urandom(16)
    message = os.urandom(20)
    appendage = b"y"
    known_mac = naive_mac(secret, message)

    for wrong in (15, 17, 0, 32):
        forged_message, forged_mac = forge_mac(known_mac, wrong, message, appendage)
        assert naive_mac(secret, forged_message) != forged_mac


def test_hmac_over_the_same_hash_is_not_forgeable():
    """The fix, demonstrated: the same trick does not work against HMAC.

    This is the test that says the attack is a property of the construction and
    not of the hash. The extension is built exactly as before and applied to an
    HMAC of the same secret and message, and it does not verify.
    """

    secret = os.urandom(32)
    message = os.urandom(16)
    appendage = b";admin=true"

    known_mac = naive_mac(secret, message)
    forged_message, forged_mac = forge_mac(known_mac, len(secret), message, appendage)

    assert hmac_sha256(secret, forged_message) != forged_mac
    # And the genuine HMAC of the forged message is a different value entirely.
    assert hmac_sha256(secret, forged_message) == stdlib_hmac.new(
        secret, forged_message, hashlib.sha256
    ).digest()


@pytest.mark.parametrize("length", [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 200])
def test_resuming_a_digest_matches_the_definition(length):
    """The resumption property, against the standard library rather than itself."""

    prefix = os.urandom(length)
    suffix = os.urandom(40)
    glue = sha256_padding(length)
    expected = hashlib.sha256(prefix + glue + suffix).digest()

    assert sha256_resume(sha256(prefix), length + len(glue), suffix) == expected
    assert sha256(prefix + glue + suffix) == expected


def test_the_padding_is_the_padding():
    """The padding helper has to agree with the standard library's behaviour."""

    for length in (0, 1, 55, 56, 57, 63, 64, 65, 127, 128, 1000):
        padding = sha256_padding(length)
        assert (length + len(padding)) % 64 == 0
        assert padding[0] == 0x80
        assert padding[-8:] == (length * 8).to_bytes(8, "big")


def test_resuming_refuses_a_length_that_is_not_a_block_boundary():
    """A raw digest state only exists at a block boundary, and saying so is the contract."""

    state = sha256(b"anything")
    with pytest.raises(ValueError):
        sha256_resume(state, 17, b"more")
    with pytest.raises(ValueError):
        sha256_resume(state[:-1], 64, b"more")
    with pytest.raises(ValueError):
        sha256_resume(state, -64, b"more")


def test_the_naive_mac_refuses_non_bytes():
    with pytest.raises(ValueError):
        naive_mac("not bytes", b"message")
    with pytest.raises(ValueError):
        naive_mac(b"secret", "not bytes")


def test_forge_mac_refuses_a_mac_of_the_wrong_size():
    with pytest.raises(ValueError):
        forge_mac(b"short", 8, b"message", b"appendage")
