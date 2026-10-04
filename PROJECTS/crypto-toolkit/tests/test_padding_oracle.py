"""The padding oracle attack.

The attack is checked by recovering a plaintext it was never given, through an
oracle that only ever says yes or no, and comparing what comes out to what went
in. The oracle is a real one -- it decrypts with the real key and strips the
real padding -- so the test is not a simulation of the vulnerability, it is the
vulnerability.

Keys, IVs and plaintexts are generated at run time. Nothing is compared against
a stored value.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.attacks.padding_oracle import padding_oracle, recover_block, recover_plaintext  # noqa: E402
from src.cbc import CBC, pkcs7_unpad  # noqa: E402


@pytest.mark.parametrize("length", [1, 15, 16, 17, 31, 32, 33, 48, 64, 100])
def test_the_plaintext_is_recovered_through_the_oracle(length):
    """One bit per query is enough to recover the whole message."""

    key = os.urandom(16)
    iv = os.urandom(16)
    plaintext = os.urandom(length)
    ciphertext = CBC(key).encrypt(iv, plaintext)

    recovered = recover_plaintext(padding_oracle(key), iv, ciphertext)

    assert pkcs7_unpad(recovered) == plaintext


def test_the_padding_itself_is_recovered_too():
    """The attack learns the padding, which is why the raw result still carries it."""

    key = os.urandom(16)
    iv = os.urandom(16)
    plaintext = os.urandom(20)
    ciphertext = CBC(key).encrypt(iv, plaintext)

    recovered = recover_plaintext(padding_oracle(key), iv, ciphertext)

    assert len(recovered) == len(ciphertext)
    assert recovered != plaintext
    assert recovered.endswith(bytes([len(recovered) - len(plaintext)]) * (len(recovered) - len(plaintext)))


def test_a_single_block_can_be_recovered_on_its_own():
    """One block, one preceding block, no key in hand.

    A 16-byte message is padded to a whole extra block, so the ciphertext is two
    blocks and the block worth recovering on its own is the padding block: its
    plaintext is entirely predictable, which makes it a clean check.
    """

    key = os.urandom(16)
    iv = os.urandom(16)
    ciphertext = CBC(key).encrypt(iv, os.urandom(16))
    assert len(ciphertext) == 32

    recovered = recover_block(padding_oracle(key), ciphertext[:16], ciphertext[16:])

    assert recovered == b"\x10" * 16


def test_the_oracle_is_a_real_oracle():
    """It has to say no as well as yes, or the attack would be reading a constant."""

    key = os.urandom(16)
    oracle = padding_oracle(key)
    iv = os.urandom(16)
    ciphertext = CBC(key).encrypt(iv, os.urandom(16))

    # The final block, presented with the block that really precedes it, carries
    # valid padding by construction.
    assert oracle(ciphertext[:16], ciphertext[16:]) is True

    accepted = sum(1 for candidate in (os.urandom(16) for _ in range(200)) if oracle(iv, candidate))
    # Random blocks satisfy PKCS#7 padding rarely -- about one in 256 for the
    # one-byte case and vanishingly often beyond it -- so a few hundred trials
    # must be overwhelmingly rejected.
    assert accepted < 20


def test_an_oracle_that_always_says_no_is_reported_rather_than_guessed_at():
    """A caller with the wrong oracle gets an error, not a made-up plaintext."""

    key = os.urandom(16)
    iv = os.urandom(16)
    ciphertext = CBC(key).encrypt(iv, os.urandom(16))

    with pytest.raises(ValueError):
        recover_plaintext(lambda preceding, block: False, iv, ciphertext)


def test_the_attack_does_not_call_the_cipher_with_the_key():
    """The attack only ever calls the oracle, and the oracle is the only thing with the key."""

    key = os.urandom(16)
    iv = os.urandom(16)
    plaintext = os.urandom(32)
    ciphertext = CBC(key).encrypt(iv, plaintext)

    queries = []

    def counting_oracle(preceding, block):
        queries.append((preceding, block))
        return padding_oracle(key)(preceding, block)

    recovered = recover_plaintext(counting_oracle, iv, ciphertext)

    assert pkcs7_unpad(recovered) == plaintext
    # Roughly 128 queries per byte, and never the key.
    assert len(queries) >= 16 * 32
    assert all(len(preceding) == 16 and len(block) == 16 for preceding, block in queries)


def test_malformed_input_is_refused():
    key = os.urandom(16)
    oracle = padding_oracle(key)
    with pytest.raises(ValueError):
        recover_block(oracle, b"short", os.urandom(16))
    with pytest.raises(ValueError):
        recover_block(oracle, os.urandom(16), b"short")
    with pytest.raises(ValueError):
        recover_plaintext(oracle, os.urandom(15), os.urandom(16))
    with pytest.raises(ValueError):
        recover_plaintext(oracle, os.urandom(16), os.urandom(17))
