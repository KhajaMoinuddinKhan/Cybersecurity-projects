"""The length-extension attack on a MAC built as ``sha256(secret || message)``.

The construction looks reasonable and is wrong. A MAC is supposed to be
unforgeable without the secret, and this one can be extended by anyone who has
seen a single message and its tag: SHA-256's digest is its internal state, and
the padding SHA-256 appends to the message is public. So an attacker who knows
the tag of ``secret || message`` and the *length* of the secret -- not its value
-- can compute the tag of ``secret || message || padding || appendage`` for any
appendage they like.

The fix is not to change the hash. It is to stop using a hash as a MAC: HMAC
over the same SHA-256 does not have this property, because the secret is used
twice and at both ends, so the state an attacker resumes is not the state the
verification will compute.
"""
from __future__ import annotations

from ..sha256 import sha256, sha256_padding, sha256_resume


def naive_mac(secret: bytes, message: bytes) -> bytes:
    """The vulnerable construction, kept here so the attack has something real to break.

    A MAC should be unforgeable; this one is not. It is written out rather than
    described because a demonstration of an attack against an imagined
    construction proves nothing.
    """

    if not isinstance(secret, (bytes, bytearray)) or not isinstance(message, (bytes, bytearray)):
        raise ValueError("the secret and the message must be bytes")
    return sha256(bytes(secret) + bytes(message))


def forge_mac(
    known_mac: bytes,
    secret_length: int,
    original_message: bytes,
    appendage: bytes,
) -> tuple[bytes, bytes]:
    """Forge a valid MAC without the secret.

    Returns ``(forged_message, forged_mac)``. The forged message is the original
    message, then the padding SHA-256 had already appended to the secret and the
    message together, then the attacker's appendage. The forged MAC is the
    original tag continued over that appendage.

    The secret is never needed: only its length, because that is what fixes the
    padding that has to be reproduced. A caller who guesses the length wrong
    gets a MAC that does not verify, which is the honest failure mode.
    """

    if not isinstance(known_mac, (bytes, bytearray)) or len(known_mac) != 32:
        raise ValueError("the known MAC must be 32 bytes")
    if secret_length < 0:
        raise ValueError("the secret length cannot be negative")
    if not isinstance(original_message, (bytes, bytearray)) or not isinstance(appendage, (bytes, bytearray)):
        raise ValueError("the message and the appendage must be bytes")
    original_message = bytes(original_message)
    appendage = bytes(appendage)

    prefix_length = secret_length + len(original_message)
    glue = sha256_padding(prefix_length)
    forged_message = original_message + glue + appendage
    forged_mac = sha256_resume(bytes(known_mac), prefix_length + len(glue), appendage)
    return forged_message, forged_mac
