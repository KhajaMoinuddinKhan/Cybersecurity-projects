"""The field GF(2**128), as GHASH defines it.

GHASH is a polynomial evaluation: the associated data and the ciphertext are
read as one long sequence of 128-bit blocks, and the tag is that sequence
evaluated at a point derived from the key. So the arithmetic underneath GCM is
multiplication in a field of polynomials over the two-element field, and it is
worth having on its own for two reasons.

The first is that the tag computation should not be the only place that can do
it. The nonce-reuse attack in ``src/attacks/`` recovers the hash subkey by
solving a polynomial whose coefficients are field elements, and if it used a
second, separate implementation of the multiplication, a disagreement between
the two would look like a failed attack rather than a bug.

The second is that the bit order here is not the obvious one. The specification
numbers the bits of a block so that the *leftmost* bit is the coefficient of
x**0, which means multiplication shifts to the right and the reduction
polynomial is applied when the *low* bit falls off the end rather than the high
one. Written the other way the arithmetic is still self-consistent -- it
multiplies, it reduces, it returns a value -- and every tag it produces is
wrong. Nothing about the output says so. That is why this file exists as a
single implementation rather than two.
"""
from __future__ import annotations

GF128_BLOCK_SIZE = 16
GF128_BITS = 128

# x**128 + x**7 + x**2 + x + 1, the reduction polynomial, written so that the
# low bit of the value is the x**127 coefficient and the wrap-around lands on
# x**128.
_REDUCTION = 0xE1000000000000000000000000000000

# The multiplicative identity. This is the trap in this representation, and it
# cost a debugging session to find: the specification's bit order makes the most
# significant bit the coefficient of x**0, so the field element 1 is the block
# with its top bit set, and the *integer* 1 is x**127. Writing `result = 1` in an
# exponentiation therefore seeds it with the wrong element, the inverse comes out
# wrong, and a polynomial division whose leading term never cancels loops
# forever rather than failing. Every place that needs the identity uses this.
GF128_ONE = 1 << (GF128_BITS - 1)


def block_to_int(block: bytes) -> int:
    """Read a 16-byte block as a field element."""

    if len(block) != GF128_BLOCK_SIZE:
        raise ValueError("a field element is 16 bytes, got %d" % len(block))
    return int.from_bytes(block, "big")


def int_to_block(value: int) -> bytes:
    """Write a field element back as 16 bytes."""

    if not 0 <= value < (1 << GF128_BITS):
        raise ValueError("a field element is 128 bits")
    return value.to_bytes(GF128_BLOCK_SIZE, "big")


def gf128_multiply(left: int, right: int) -> int:
    """Multiply two field elements, as GCM's GHASH defines the operation.

    Both arguments are 128-bit integers whose most significant bit is the
    coefficient of x**0 in the specification's notation. The loop walks the bits
    of ``left`` from the top, accumulating ``right`` shifted right by one each
    time, and applies the reduction polynomial whenever a bit falls off the
    bottom.
    """

    product = 0
    value = right
    for index in range(GF128_BITS):
        if (left >> (GF128_BITS - 1 - index)) & 1:
            product ^= value
        if value & 1:
            value = (value >> 1) ^ _REDUCTION
        else:
            value >>= 1
    return product


def gf128_power(value: int, exponent: int) -> int:
    """Raise a field element to a power, by squaring and multiplying.

    The exponent is an ordinary integer, not a field element: this is the
    exponentiation that makes the inverse and the square root below possible.
    """

    if exponent < 0:
        raise ValueError("the exponent must not be negative")
    result = GF128_ONE
    base = value
    while exponent:
        if exponent & 1:
            result = gf128_multiply(result, base)
        base = gf128_multiply(base, base)
        exponent >>= 1
    return result


def gf128_inverse(value: int) -> int:
    """Return the multiplicative inverse, or raise for zero.

    Every non-zero element of a finite field has an inverse, and it is
    ``value ** (2**128 - 2)`` because the multiplicative group has order
    ``2**128 - 1``. Zero is the one element without one, and it is refused
    rather than silently returning zero.
    """

    if value == 0:
        raise ValueError("zero has no inverse in GF(2**128)")
    return gf128_power(value, (1 << GF128_BITS) - 2)


def gf128_square_root(value: int) -> int:
    """Return the unique element whose square is ``value``.

    Squaring is a bijection on GF(2**128) -- the field is perfect, so every
    element has exactly one square root -- and it is ``value ** (2**127)``,
    because raising that to the power two gives ``value ** (2**128)``, which is
    ``value`` again. This is what makes the nonce-reuse attack cheap: two
    messages of the same length under one nonce give an equation whose unknown
    appears squared, and a square root finishes it.
    """

    return gf128_power(value, 1 << (GF128_BITS - 1))
