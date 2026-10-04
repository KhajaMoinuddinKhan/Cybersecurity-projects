"""The nonce-reuse attack on AES-GCM, sometimes called the forbidden attack.

GCM's confidentiality rests entirely on the counter block never repeating under
one key. Reuse a nonce and three things fall over at once, in increasing order of
seriousness.

The first is that the keystream is identical for both messages, so the two
ciphertexts XOR to the two plaintexts XORed -- anyone who knows or can guess one
plaintext reads the other straight off.

The second is that the same keystream lets an attacker encrypt under that nonce
without the key at all, so a forged message can be built to order.

The third is the one that ends the key. The tag is GHASH of the message XORed
with a mask that depends only on the nonce, so two tags under one nonce differ
by the difference of two GHASH values -- and GHASH is a polynomial in the hash
subkey H. Two messages therefore give one equation in one unknown, and H is a
root of a polynomial whose coefficients are all public. Recover H and the
attacker can forge a valid tag for any message under that nonce, which defeats
the authentication entirely even though the key was never touched.

The polynomial is solved properly here rather than by assuming a shape for it:
the roots in GF(2**128) are found with the standard square-free step (a greatest
common divisor against x**(2**128) - x) followed by Cantor-Zassenhaus splitting
with the trace map. That matters because the shape of the polynomial depends on
whether the two messages have the same length and the same associated data, and
an attack that only worked for one of those cases would be a demonstration of
the easy case rather than of the weakness.
"""
from __future__ import annotations

import random

from ..aes import xor_bytes
from ..gcm import GCM_BLOCK_SIZE, ghash
from ..gf128 import GF128_ONE, block_to_int, gf128_inverse, gf128_multiply, int_to_block

# The split in the root finder needs random polynomials. A fixed seed makes a
# failure reproducible; the loop retries, so the seed cannot make it fail.
_RANDOM = random.Random(0x47434D)


# --------------------------------------------------------------------------
# Polynomials over GF(2**128). A polynomial is a list of field elements where
# the index is the power of x, so [c0, c1, c2] is c0 + c1*x + c2*x**2.
# --------------------------------------------------------------------------

def _trim(poly):
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly


def _poly_xor(left, right):
    out = [0] * max(len(left), len(right))
    for index in range(len(out)):
        a = left[index] if index < len(left) else 0
        b = right[index] if index < len(right) else 0
        out[index] = a ^ b
    return _trim(out)


def _poly_multiply(left, right):
    left = _trim(list(left))
    right = _trim(list(right))
    out = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        if a:
            for j, b in enumerate(right):
                if b:
                    out[i + j] ^= gf128_multiply(a, b)
    return _trim(out)


def _poly_square(poly):
    poly = _trim(list(poly))
    out = [0] * (2 * len(poly) - 1)
    for index, coefficient in enumerate(poly):
        if coefficient:
            out[2 * index] = gf128_multiply(coefficient, coefficient)
    return _trim(out)


def _poly_divmod(dividend, divisor):
    dividend = _trim(list(dividend))
    divisor = _trim(list(divisor))
    if divisor == [0]:
        raise ValueError("cannot divide by the zero polynomial")
    quotient = [0] * max(1, len(dividend) - len(divisor) + 1)
    # Every modulus this file divides by is monic, so the common case needs no
    # inversion at all. An inversion is 128 field multiplications and the root
    # finder divides thousands of times, so skipping it is the difference
    # between a second and a minute.
    lead_inverse = GF128_ONE if divisor[-1] == GF128_ONE else gf128_inverse(divisor[-1])
    while len(dividend) >= len(divisor) and dividend != [0]:
        shift = len(dividend) - len(divisor)
        factor = gf128_multiply(dividend[-1], lead_inverse)
        if factor:
            quotient[shift] ^= factor
            for index, coefficient in enumerate(divisor):
                dividend[shift + index] ^= gf128_multiply(factor, coefficient)
        dividend = _trim(dividend)
    return _trim(quotient), dividend


def _poly_mod(dividend, modulus):
    return _poly_divmod(dividend, modulus)[1]


def _poly_monic(poly):
    poly = _trim(list(poly))
    if poly == [0]:
        return poly
    inverse = gf128_inverse(poly[-1])
    return [gf128_multiply(coefficient, inverse) for coefficient in poly]


def _poly_gcd(left, right):
    left = _trim(list(left))
    right = _trim(list(right))
    while right != [0]:
        left, right = right, _poly_mod(left, right)
    return _poly_monic(left)


def _poly_power_mod(base, exponent, modulus):
    result = [GF128_ONE]
    base = _poly_mod(base, modulus)
    while exponent:
        if exponent & 1:
            result = _poly_mod(_poly_multiply(result, base), modulus)
        base = _poly_mod(_poly_square(base), modulus)
        exponent >>= 1
    return result


def _trace_mod(poly, modulus):
    """The trace of ``poly`` modulo ``modulus``: u + u**2 + ... + u**(2**127).

    The trace lands in GF(2), so for each root r of the modulus it is either 0
    or 1. That is what makes it useful: sharing a greatest common divisor with
    the modulus separates the roots into two groups, and repeating with fresh
    random polynomials eventually isolates each one.
    """

    term = _poly_mod(poly, modulus)
    total = list(term)
    for _ in range(127):
        term = _poly_mod(_poly_square(term), modulus)
        total = _poly_xor(total, term)
    return total


def _split_roots(poly):
    """Pull the linear factors out of a polynomial that is a product of them."""

    poly = _poly_monic(poly)
    if len(poly) == 1:
        return []                      # a constant, so no roots
    if len(poly) == 2:
        return [poly[0]]               # x + c has the single root c

    for _ in range(400):
        candidate = [0] + [_RANDOM.randrange(1 << 128) for _ in range(len(poly) - 2)]
        shared = _poly_gcd(poly, _trace_mod(candidate, poly))
        if 1 < len(shared) < len(poly):
            quotient, remainder = _poly_divmod(poly, shared)
            if remainder != [0]:
                continue
            return _split_roots(shared) + _split_roots(quotient)
    raise ValueError("the root finder could not split the polynomial")


def _roots(poly):
    """Every root of ``poly`` that lies in GF(2**128)."""

    poly = _poly_monic(poly)
    if len(poly) <= 1:
        return []
    if len(poly) == 2:
        return [poly[0]]

    # gcd(poly, x**(2**128) - x) is the product of the distinct linear factors,
    # because x**(2**128) - x is exactly the product of (x - r) over every r in
    # the field.
    x = [0, GF128_ONE]
    power = list(x)
    for _ in range(128):
        power = _poly_mod(_poly_square(power), poly)
    return _split_roots(_poly_gcd(poly, _poly_xor(power, x)))


# --------------------------------------------------------------------------
# The attack
# --------------------------------------------------------------------------

def _ghash_blocks(aad: bytes, ciphertext: bytes) -> list[int]:
    """The block sequence GHASH consumes, in order, as field elements."""

    blocks = []
    for offset in range(0, len(aad), GCM_BLOCK_SIZE):
        blocks.append(block_to_int(aad[offset:offset + GCM_BLOCK_SIZE].ljust(GCM_BLOCK_SIZE, b"\x00")))
    for offset in range(0, len(ciphertext), GCM_BLOCK_SIZE):
        blocks.append(block_to_int(ciphertext[offset:offset + GCM_BLOCK_SIZE].ljust(GCM_BLOCK_SIZE, b"\x00")))
    blocks.append((len(aad) * 8) << 64 | (len(ciphertext) * 8))
    return blocks


def _ghash_polynomial(aad: bytes, ciphertext: bytes) -> list[int]:
    """GHASH as a polynomial in H, with the public message as its coefficients.

    GHASH is ``sum over i of X_i * H**(n - i)`` for the n input blocks X, so the
    coefficient of H**k is the block n - k blocks from the start. The constant
    term is zero: every term carries at least one factor of H.
    """

    blocks = _ghash_blocks(aad, ciphertext)
    count = len(blocks)
    coefficients = [0] * (count + 1)
    for index, block in enumerate(blocks):
        coefficients[count - index] = block
    return coefficients


def candidate_hash_subkeys(
    tag1: bytes, aad1: bytes, ciphertext1: bytes,
    tag2: bytes, aad2: bytes, ciphertext2: bytes,
) -> list[bytes]:
    """Every hash subkey consistent with two messages that share a nonce.

    The two tags differ by the difference of two GHASH values, because the mask
    that depends only on the nonce cancels. Setting that difference to zero
    gives a polynomial in H whose roots are the candidates.
    """

    for tag in (tag1, tag2):
        if not isinstance(tag, (bytes, bytearray)) or len(tag) != GCM_BLOCK_SIZE:
            raise ValueError("a tag is 16 bytes")
    first = _ghash_polynomial(bytes(aad1), bytes(ciphertext1))
    second = _ghash_polynomial(bytes(aad2), bytes(ciphertext2))
    difference = _poly_xor(first, second)
    if len(difference) < 1:
        difference = [0]
    difference[0] ^= block_to_int(bytes(tag1)) ^ block_to_int(bytes(tag2))
    return [int_to_block(root) for root in _roots(_trim(difference))]


def recover_hash_subkey(messages: list[tuple[bytes, bytes, bytes]]) -> bytes:
    """The hash subkey, from three or more messages that share one nonce.

    One pair is not enough, and that is part of the attack rather than a
    limitation of it. Two tags differ by the difference of two GHASH values,
    which is a polynomial in H whose degree is the message length in blocks, and
    *every* root of that polynomial in GF(2**128) is a candidate -- all of them
    genuine roots, only one of them the subkey. A second pair under the same
    nonce gives a second candidate set, and the subkey is what the sets share.
    Three messages are therefore what it takes, which is worth knowing: the
    weakness is not "one pair and the key falls out" but "the same nonce twice
    already narrows the key to a handful of possibilities".

    Each message is ``(tag, aad, ciphertext)``.
    """

    if len(messages) < 3:
        raise ValueError(
            "one pair of messages leaves several candidate subkeys, all of them "
            "genuine roots, so at least three messages under the same nonce are "
            "needed to narrow it to one"
        )
    first = messages[0]
    shared = None
    for other in messages[1:]:
        candidates = set(candidate_hash_subkeys(first[0], first[1], first[2],
                                                other[0], other[1], other[2]))
        shared = candidates if shared is None else shared & candidates
        if not shared:
            raise ValueError(
                "no hash subkey is consistent with every pair, so these messages "
                "were probably not produced under a single nonce"
            )
    if len(shared) > 1:
        raise ValueError(
            "these messages leave %d candidate hash subkeys; another message "
            "under the same nonce would narrow it further" % len(shared)
        )
    return shared.pop()


def recover_keystream(ciphertext: bytes, known_plaintext: bytes) -> bytes:
    """The keystream, from a ciphertext and the plaintext it was made from.

    Under a repeated nonce this is the whole of the confidentiality failure: the
    keystream is a function of the key and the nonce only, so recovering it once
    decrypts every other message under that nonce and encrypts new ones.
    """

    if not isinstance(ciphertext, (bytes, bytearray)) or not isinstance(known_plaintext, (bytes, bytearray)):
        raise ValueError("the ciphertext and the plaintext must be bytes")
    if len(known_plaintext) > len(ciphertext):
        raise ValueError("the known plaintext cannot be longer than the ciphertext")
    return xor_bytes(bytes(ciphertext[:len(known_plaintext)]), bytes(known_plaintext))


def recover_plaintext(ciphertext: bytes, keystream: bytes) -> bytes:
    """Decrypt as much of ``ciphertext`` as the recovered keystream covers."""

    if len(keystream) > len(ciphertext):
        raise ValueError("the keystream cannot be longer than the ciphertext")
    return xor_bytes(bytes(ciphertext[:len(keystream)]), bytes(keystream))


def recover_plaintext_pair(ciphertext1: bytes, ciphertext2: bytes, known_plaintext: bytes) -> bytes:
    """Recover the second plaintext from the first, given a repeated nonce.

    Only the part both messages share is recoverable, because only there is the
    keystream common to them.
    """

    keystream = recover_keystream(ciphertext1, known_plaintext)
    shared = min(len(keystream), len(ciphertext2))
    return xor_bytes(bytes(ciphertext2[:shared]), keystream[:shared])


def nonce_mask(tag: bytes, aad: bytes, ciphertext: bytes, hash_subkey: bytes) -> bytes:
    """The mask that depends only on the nonce: ``tag XOR GHASH``.

    With the hash subkey in hand, one known tag gives this away, and it is the
    same for every message under that nonce. It is what turns a recovered
    subkey into the ability to forge.
    """

    return xor_bytes(bytes(tag), ghash(bytes(hash_subkey), bytes(aad), bytes(ciphertext)))


def forge_tag(
    hash_subkey: bytes,
    tag: bytes, aad: bytes, ciphertext: bytes,
    new_aad: bytes, new_ciphertext: bytes,
) -> bytes:
    """Forge a tag the real implementation will accept, under the reused nonce.

    The new message can be anything, including one the attacker just built from
    the recovered keystream. What it cannot be is a message under a *different*
    nonce: that would need the key, not just the subkey.
    """

    mask = nonce_mask(tag, aad, ciphertext, hash_subkey)
    return xor_bytes(mask, ghash(bytes(hash_subkey), bytes(new_aad), bytes(new_ciphertext)))
