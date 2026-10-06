"""Keccak-f[1600] and the six SHA-3 functions of FIPS 202.

ML-KEM is built on this, so it lives here rather than inside `src/mlkem.py`:
the permutation is a primitive with its own standard and its own published
vectors, and a bug in it would otherwise surface as a lattice that does not
reproduce its test vectors, which is a much harder thing to read.

The six functions share one sponge. SHA3-224, SHA3-256, SHA3-384, SHA3-512,
SHAKE128 and SHAKE256 differ only in the rate and in two bits of domain
separation, so they are written once and parameterised rather than six times.
Writing them out separately is how they drift apart.
"""

from __future__ import annotations

__all__ = [
    "KECCAK_LANES",
    "SHA3_224_RATE",
    "SHA3_256_RATE",
    "SHA3_384_RATE",
    "SHA3_512_RATE",
    "SHAKE128_RATE",
    "SHAKE256_RATE",
    "SHA3_DOMAIN_SUFFIX",
    "SHAKE_DOMAIN_SUFFIX",
    "keccak_f1600",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "sha3_256_hex",
    "shake_128",
    "shake_256",
]

KECCAK_LANES = 25                      # a 5x5 array of 64-bit lanes: 1600 bits
KECCAK_ROUNDS = 24
_MASK64 = (1 << 64) - 1

# The rate is the block size the message is absorbed in: 1600 minus twice the
# capacity, which FIPS 202 fixes per function. Capacity is 2*digest_length for
# the hash functions and 2*security_level for the XOFs.
SHA3_224_RATE = 144                    # (1600 - 2*224) / 8
SHA3_256_RATE = 136                    # (1600 - 2*256) / 8
SHA3_384_RATE = 104                    # (1600 - 2*384) / 8
SHA3_512_RATE = 72                     # (1600 - 2*512) / 8
SHAKE128_RATE = 168                    # (1600 - 2*128) / 8
SHAKE256_RATE = 136                    # (1600 - 2*256) / 8

# FIPS 202 Section 6.1 appends the bits 01 to a hash message and 1111 to an XOF
# message, before the pad10*1 rule. Those bits land in the low end of the first
# padding byte, so the suffix is that byte: 0b00000110 and 0b00011111. The
# final 1 of pad10*1 is the high bit of the last block byte, set in _sponge.
SHA3_DOMAIN_SUFFIX = 0x06
SHAKE_DOMAIN_SUFFIX = 0x1F

# FIPS 202 Table 2: the rotation offsets of the rho step, indexed [x][y].
_RHO = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

# FIPS 202 Algorithm 5: rc(t) over 24 rounds. These are the standard constants,
# and `tests/test_keccak.py` derives them from the LFSR of the standard rather
# than trusting this table.
_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)


def _rotl(value: int, shift: int) -> int:
    """Rotate a 64-bit lane left. A shift of 0 is the identity."""
    if shift == 0:
        return value & _MASK64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def keccak_f1600(state: list[int]) -> None:
    """The KECCAK-p[1600, 24] permutation, applied to `state` in place.

    `state` is 25 lanes, indexed `x + 5*y`. It is modified, not replaced, so a
    caller absorbing several blocks does not copy the array between them.
    """
    if len(state) != KECCAK_LANES:
        raise ValueError(f"the state is {KECCAK_LANES} lanes, not {len(state)}")

    for round_constant in _ROUND_CONSTANTS:
        # theta: each lane takes the parity of its column, mixed with the
        # neighbouring columns. This is the only step that mixes across x.
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            dx = d[x]
            for y in range(5):
                state[x + 5 * y] ^= dx

        # rho and pi together: rotate each lane by its offset and move it to
        # B[y][2x + 3y]. Doing them in one pass is the standard's own
        # presentation and avoids a second 25-lane array.
        b = [0] * KECCAK_LANES
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(state[x + 5 * y], _RHO[x][y])

        # chi: the only non-linear step, and the reason the permutation is not
        # a linear map over GF(2).
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (b[x + 5 * y]
                                    ^ ((~b[(x + 1) % 5 + 5 * y]) & _MASK64)
                                    & b[(x + 2) % 5 + 5 * y])

        # iota: break the symmetry between rounds.
        state[0] ^= round_constant


def _sponge(data: bytes, rate: int, suffix: int, out_length: int) -> bytes:
    """Absorb `data`, then squeeze `out_length` bytes.

    The padding is pad10*1 from FIPS 202 Section 5.1 with the domain suffix of
    Section 6.1 folded in: the suffix byte is appended and the high bit of the
    final block byte is set. When the message plus suffix exactly fills a block
    those are the same byte, which is why the suffix is applied before the
    zero-padding rather than after it.
    """
    if out_length < 0:
        raise ValueError("the output length cannot be negative")

    padded = bytearray(data)
    padded.append(suffix)
    while len(padded) % rate:
        padded.append(0)
    padded[-1] ^= 0x80

    state = [0] * KECCAK_LANES
    lanes_per_block = rate // 8
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(lanes_per_block):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        keccak_f1600(state)

    out = bytearray()
    while len(out) < out_length:
        for i in range(lanes_per_block):
            out += state[i].to_bytes(8, "little")
            if len(out) >= out_length:
                break
        if len(out) < out_length:
            keccak_f1600(state)
    return bytes(out[:out_length])


def sha3_224(data: bytes) -> bytes:
    return _sponge(data, SHA3_224_RATE, SHA3_DOMAIN_SUFFIX, 28)


def sha3_256(data: bytes) -> bytes:
    return _sponge(data, SHA3_256_RATE, SHA3_DOMAIN_SUFFIX, 32)


def sha3_384(data: bytes) -> bytes:
    return _sponge(data, SHA3_384_RATE, SHA3_DOMAIN_SUFFIX, 48)


def sha3_512(data: bytes) -> bytes:
    return _sponge(data, SHA3_512_RATE, SHA3_DOMAIN_SUFFIX, 64)


def sha3_256_hex(data: bytes) -> str:
    return sha3_256(data).hex()


def shake_128(data: bytes, length: int) -> bytes:
    """SHAKE128 with an output of exactly `length` bytes."""
    return _sponge(data, SHAKE128_RATE, SHAKE_DOMAIN_SUFFIX, length)


def shake_256(data: bytes, length: int) -> bytes:
    """SHAKE256 with an output of exactly `length` bytes."""
    return _sponge(data, SHAKE256_RATE, SHAKE_DOMAIN_SUFFIX, length)
