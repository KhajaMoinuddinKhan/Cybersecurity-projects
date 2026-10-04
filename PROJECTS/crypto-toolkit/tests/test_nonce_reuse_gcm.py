"""The nonce-reuse attack on AES-GCM.

The attack is checked against the genuine implementation at every step: the
recovered subkey is compared to the subkey the key actually has, the recovered
plaintext to the plaintext that was encrypted, and the forged tag to the tag the
real GCM would have produced. Nothing here is compared to a stored value, and
every key, nonce and message is generated at run time.

One thing this file deliberately records is that a single pair of messages is
*not* enough. The difference of two tags is a polynomial in the subkey whose
every root is a genuine candidate, so a pair leaves a handful of possibilities
and three messages are needed to pin the subkey down. That is the shape of the
real weakness and a test that hid it would be describing a different attack.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.attacks.nonce_reuse_gcm import (  # noqa: E402
    candidate_hash_subkeys,
    forge_tag,
    nonce_mask,
    recover_hash_subkey,
    recover_keystream,
    recover_plaintext,
    recover_plaintext_pair,
)
from src.gcm import GCM, InvalidTag  # noqa: E402


def _messages(key, nonce, count, sizes=None, aads=None):
    """Encrypt several distinct messages under one nonce and return the triples."""

    out = []
    for index in range(count):
        size = (sizes or [16, 32, 48])[index % len(sizes or [16, 32, 48])]
        aad = (aads or [b"", b"", b"header"])[index % len(aads or [b"", b"", b"header"])]
        plaintext = os.urandom(size)
        ciphertext, tag = GCM(key).encrypt(nonce, plaintext, aad)
        out.append((tag, aad, ciphertext))
    return out


@pytest.mark.parametrize("sizes,aads", [
    ([16, 16, 16], [b"", b"", b""]),
    ([16, 32, 48], [b"", b"", b""]),
    ([32, 32, 32], [b"header", b"header", b"header"]),
    ([32, 32, 32], [b"", b"header", b"longer-header"]),
    ([64, 80, 96], [b"aad-block!", b"aad-block!", b"aad-block!"]),
    ([0, 16, 32], [b"", b"", b""]),
])
def test_the_subkey_is_recovered_from_three_messages(sizes, aads):
    """The headline: the hash subkey comes out of three messages under one nonce."""

    key = os.urandom(16)
    nonce = os.urandom(12)
    messages = _messages(key, nonce, 3, sizes, aads)

    recovered = recover_hash_subkey(messages)

    assert recovered == GCM(key).hash_subkey


def test_one_pair_leaves_candidates_that_are_all_genuine():
    """A pair does not pin the subkey down, and every candidate it offers is real.

    "Genuine" is checked without the key: a candidate is real exactly when the
    mask it implies is the same for both messages, because the mask depends only
    on the nonce.
    """

    key = os.urandom(16)
    nonce = os.urandom(12)
    messages = _messages(key, nonce, 2, [16, 48], [b"", b""])
    (tag1, aad1, ciphertext1), (tag2, aad2, ciphertext2) = messages

    candidates = candidate_hash_subkeys(tag1, aad1, ciphertext1, tag2, aad2, ciphertext2)

    assert candidates, "a real pair must offer at least one candidate"
    assert GCM(key).hash_subkey in candidates
    for candidate in candidates:
        assert nonce_mask(tag1, aad1, ciphertext1, candidate) == nonce_mask(
            tag2, aad2, ciphertext2, candidate
        )


def test_recovering_from_a_pair_alone_is_refused():
    """The API says out loud what the mathematics says: two are not enough."""

    key = os.urandom(16)
    nonce = os.urandom(12)
    with pytest.raises(ValueError):
        recover_hash_subkey(_messages(key, nonce, 2))


def test_messages_under_different_nonces_do_not_agree():
    """If the messages were not under one nonce, there is no common candidate."""

    key = os.urandom(16)
    messages = (_messages(key, os.urandom(12), 1)
                + _messages(key, os.urandom(12), 2))
    with pytest.raises(ValueError):
        recover_hash_subkey(messages)


def test_the_other_plaintext_falls_out_of_the_repeated_keystream():
    """Confidentiality goes first, before any of the tag arithmetic."""

    key = os.urandom(16)
    nonce = os.urandom(12)
    first = os.urandom(48)
    second = os.urandom(48)
    ciphertext1, _ = GCM(key).encrypt(nonce, first)
    ciphertext2, _ = GCM(key).encrypt(nonce, second)

    assert recover_plaintext_pair(ciphertext1, ciphertext2, first) == second


def test_a_forged_tag_is_accepted_by_the_real_gcm():
    """Authentication goes too: the genuine decrypt accepts a message nobody signed."""

    key = os.urandom(16)
    nonce = os.urandom(12)
    messages = _messages(key, nonce, 3)
    subkey = recover_hash_subkey(messages)

    known_tag, known_aad, known_ciphertext = messages[0]
    chosen = b"transfer 999999 to mallory"
    chosen_ciphertext, chosen_tag = GCM(key).encrypt(nonce, chosen)

    forged = forge_tag(subkey, known_tag, known_aad, known_ciphertext,
                       b"", chosen_ciphertext)

    assert forged == chosen_tag
    assert GCM(key).decrypt(nonce, chosen_ciphertext, forged) == chosen


def test_the_forgery_works_only_under_the_reused_nonce():
    """The boundary of the attack: a different nonce needs the key, not the subkey."""

    key = os.urandom(16)
    nonce = os.urandom(12)
    messages = _messages(key, nonce, 3)
    subkey = recover_hash_subkey(messages)
    known_tag, known_aad, known_ciphertext = messages[0]

    chosen = os.urandom(32)
    other_nonce = os.urandom(12)
    other_ciphertext, other_tag = GCM(key).encrypt(other_nonce, chosen)

    forged = forge_tag(subkey, known_tag, known_aad, known_ciphertext, b"", other_ciphertext)

    assert forged != other_tag
    with pytest.raises(InvalidTag):
        GCM(key).decrypt(other_nonce, other_ciphertext, forged)


def test_the_keystream_lets_the_attacker_encrypt_without_the_key():
    """With the keystream recovered, the attacker can build a ciphertext to order."""

    key = os.urandom(16)
    nonce = os.urandom(12)
    known = os.urandom(40)
    ciphertext, _ = GCM(key).encrypt(nonce, known)

    keystream = recover_keystream(ciphertext, known)
    chosen = os.urandom(40)
    attacker_ciphertext = recover_plaintext(chosen, keystream)

    real_ciphertext, _ = GCM(key).encrypt(nonce, chosen)
    assert attacker_ciphertext == real_ciphertext


def test_recovering_a_plaintext_needs_a_plaintext_to_start_from():
    """The attack is not a break of the cipher on its own: it needs one known message."""

    key = os.urandom(16)
    nonce = os.urandom(12)
    first = os.urandom(16)
    ciphertext1, _ = GCM(key).encrypt(nonce, first)
    ciphertext2, _ = GCM(key).encrypt(nonce, os.urandom(16))

    # XORing the ciphertexts gives the XOR of the plaintexts, which is the whole
    # of what is recoverable without knowing one of them.
    from src.aes import xor_bytes
    assert xor_bytes(ciphertext1, ciphertext2) != first
    assert xor_bytes(xor_bytes(ciphertext1, ciphertext2), first) == recover_plaintext_pair(
        ciphertext1, ciphertext2, first
    )


def test_a_different_nonce_under_the_same_key_is_safe():
    """The control: with distinct nonces the same attack recovers nothing."""

    key = os.urandom(16)
    first = os.urandom(32)
    second = os.urandom(32)
    ciphertext1, tag1 = GCM(key).encrypt(os.urandom(12), first)
    ciphertext2, tag2 = GCM(key).encrypt(os.urandom(12), second)

    candidates = candidate_hash_subkeys(tag1, b"", ciphertext1, tag2, b"", ciphertext2)
    assert GCM(key).hash_subkey not in candidates


def test_malformed_input_is_refused():
    key = os.urandom(16)
    nonce = os.urandom(12)
    ciphertext, tag = GCM(key).encrypt(nonce, os.urandom(16))

    with pytest.raises(ValueError):
        candidate_hash_subkeys(b"short", b"", ciphertext, tag, b"", ciphertext)
    with pytest.raises(ValueError):
        recover_keystream(ciphertext, os.urandom(len(ciphertext) + 1))
    with pytest.raises(ValueError):
        recover_plaintext(ciphertext, os.urandom(len(ciphertext) + 1))
    with pytest.raises(ValueError):
        recover_hash_subkey([(tag, b"", ciphertext)])
