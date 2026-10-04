"""The nonce-reuse attack on ECDSA, which recovers the private key outright.

ECDSA signs by picking a secret nonce k, computing the point k*G, and forming
two numbers from it and the private key d:

    r = (k*G).x  mod n
    s = k^-1 * (z + r*d)  mod n

Two signatures that used the same k share an r, and that is the whole weakness.
Subtracting the two equations makes d and r*d cancel in a way that leaves k
alone:

    s1 - s2 = k^-1 * (z1 - z2)      so      k = (z1 - z2) / (s1 - s2)

and with k known the first equation inverts straight to the private key:

    d = (s1 * k - z1) / r

Everything in that is public except d, which is why this is the failure that
ended real systems. It is also why RFC 6979 exists and why this project
implements it: a nonce derived from the key and the message can never repeat,
so the arithmetic above has nothing to work with.

Unlike the GCM attack, this one needs no root finding and no second message
beyond the two signatures. Two signatures, one repeated nonce, one key.
"""
from __future__ import annotations

from ..ecdsa import P256_N, digest_to_int


def recover_nonce(
    digest1: bytes, signature1: tuple[int, int],
    digest2: bytes, signature2: tuple[int, int],
    order: int = P256_N,
) -> int:
    """Recover the nonce the two signatures share.

    ``signature`` is ``(r, s)``. The two signatures must carry the same ``r``,
    because ``r`` is a function of the nonce: if they differ, the nonces differed
    and there is nothing here to recover.
    """

    r1, s1 = signature1
    r2, s2 = signature2
    if r1 != r2:
        raise ValueError(
            "the two signatures have different r values, so their nonces were "
            "different and there is nothing to recover"
        )
    if s1 == s2:
        raise ValueError("the two signatures are identical, so there is nothing to subtract")
    z1 = digest_to_int(digest1)
    z2 = digest_to_int(digest2)
    difference = (s1 - s2) % order
    if difference == 0:
        raise ValueError("s1 and s2 are equal modulo the order")
    return (z1 - z2) * pow(difference, -1, order) % order


def recover_private_key(
    digest1: bytes, signature1: tuple[int, int],
    digest2: bytes, signature2: tuple[int, int],
    order: int = P256_N,
) -> int:
    """Recover the private key from two signatures that share a nonce."""

    r1, s1 = signature1
    if r1 % order == 0:
        raise ValueError("r is zero modulo the order, which cannot be inverted")
    nonce = recover_nonce(digest1, signature1, digest2, signature2, order)
    z1 = digest_to_int(digest1)
    return (s1 * nonce - z1) * pow(r1 % order, -1, order) % order
