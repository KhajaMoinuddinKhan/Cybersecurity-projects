"""RSA with OAEP, from the PKCS #1 specification.

Three layers are written out here, because each one has a failure mode that is
invisible from the layer above.

The first is modular exponentiation over a composite modulus. The public
operation is one ``pow(m, e, n)``. The private operation is not: computing
``pow(c, d, n)`` directly is correct but roughly four times slower than the
Chinese Remainder Theorem form, and the CRT form carries a hazard of its own. If
the arithmetic is faulted -- a single bit of ``p`` or of ``dp`` flipped by a
glitch, or by an attacker with physical access -- the CRT reconstructs a
plaintext that is wrong yet internally consistent with the two halves. The
defence is to re-encrypt the result and compare it to the ciphertext. A wrong
plaintext almost never re-encrypts to the original ``c``, so a fault becomes a
refusal instead of a silently corrupted message. That check is why
:func:`rsadp` is a function rather than a single line of arithmetic.

The second is OAEP. Raw RSA is deterministic and malleable: the same plaintext
always gives the same ciphertext, and multiplying a ciphertext by ``s**e``
multiplies the recovered plaintext by ``s``. OAEP removes both properties by
wrapping the message in a randomised structure before the exponentiation, with
the randomness (a seed) expanded by a mask generation function and XORed across
the rest of the block. Decoding reverses that and then has to *reject*: the
leading byte must be zero, the label hash must match, and a ``0x01`` separator
must be present. A decoder that reported which of those failed would be an
oracle -- the padding attack in this repository is exactly that oracle -- so
every check is folded into one verdict and one exception.

The third is the mask generation function and the hash beneath it. MGF1 is a
counter-mode expansion of a hash: ``SHA-256(seed || counter)`` for a 32-bit
counter, concatenated until the requested length is reached. It is built on
``src/sha256.py`` rather than on ``hashlib`` because this module may import only
that primitive and the standard library, and because the published vectors are
the external check on whether the hash is right -- a bug there shows up as a
wrong mask and a failed decryption on every vector at once.

Key generation is Miller-Rabin. For small candidates a fixed set of bases is a
*proof* of primality rather than a probabilistic test; for the large candidates
that key generation actually uses, the first several prime bases are combined
with random ones, which drives the error probability below any practical
concern. The two primes are drawn with their top two bits set, so their product
is guaranteed to carry the full modulus bit length instead of occasionally
coming back one bit short.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from math import gcd

from .sha256 import sha256

RSA_PUBLIC_EXPONENT = 65537
OAEP_HASH_LENGTH = 32

# The bases whose use is a proof of primality for every candidate below the
# bound that follows, and the start of the random set for larger candidates.
_MILLER_RABIN_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

# A published result: testing these twelve prime bases is deterministic for
# every n below 3.3 * 10**24, which covers anything a caller might use for a toy
# key. Above it the prime bases are kept and random bases are added.
_DETERMINISTIC_LIMIT = 3_317_044_064_679_887_385_961_981

_RANDOM_BASES = 24


class DecryptionError(ValueError):
    """Raised for any ciphertext that does not decrypt.

    One exception covers a wrong length, a representative outside ``[0, n)``
    and an OAEP block that does not decode. That is deliberate: a decoder that
    told the caller *which* check failed is the oracle the padding attack in
    this repository exists to demonstrate.
    """


@dataclass(frozen=True)
class RSAPublicKey:
    """The public half: the modulus and the public exponent."""

    n: int
    e: int

    def size_bytes(self) -> int:
        """Return ``k``, the modulus length in bytes.

        This is the length of every ciphertext and of the OAEP encoded message,
        so it is the value every length check in this module is measured
        against.
        """

        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True)
class RSAPrivateKey:
    """The private half, in the CRT form rather than as a single exponent.

    ``dp`` and ``dq`` are ``d`` reduced modulo ``p - 1`` and ``q - 1``, and
    ``qinv`` is the inverse of ``q`` modulo ``p``. Carrying them means the
    private exponentiation is two half-size ones plus a recombination, and it is
    the recombination that :func:`rsadp` re-checks.
    """

    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qinv: int


# ---------------------------------------------------------------------------
# Uniform random integers and primality.
# ---------------------------------------------------------------------------


def _random_below(low: int, high: int) -> int:
    """Return a uniform integer in ``[low, high)`` drawn from ``os.urandom``.

    The bytes are read as a big-endian integer and rejected until they fall in
    range, which is uniform; taking the value modulo the span instead would
    favour the low end whenever the span does not divide a power of two.
    """

    span = high - low
    if span <= 0:
        raise ValueError("the range must be non-empty")
    width = (span.bit_length() + 7) // 8
    while True:
        candidate = int.from_bytes(os.urandom(width), "big")
        if candidate < span:
            return low + candidate


def _is_probable_prime(n: int) -> bool:
    """Return whether ``n`` passes Miller-Rabin.

    Small factors are divided out first, which settles most composites before
    any exponentiation. The remaining candidates are written as ``n - 1 =
    2**power * d`` and tested against each base: the base must be a witness to
    primality, meaning ``base**d mod n`` is one or the loop of squarings reaches
    ``n - 1``. A candidate that fails for any base is composite.

    The base set is the twelve small primes, which is deterministic below
    :data:`_DETERMINISTIC_LIMIT`, plus random bases for larger candidates. The
    random bases are the part that matters in practice: twelve fixed bases are
    enough against any adversary who is not specifically targeting them, and the
    random ones make even that useless.
    """

    if n < 2:
        return False
    for prime in _MILLER_RABIN_BASES:
        if n % prime == 0:
            return n == prime

    d = n - 1
    power = 0
    while d % 2 == 0:
        d //= 2
        power += 1

    if n < _DETERMINISTIC_LIMIT:
        bases = _MILLER_RABIN_BASES
    else:
        bases = _MILLER_RABIN_BASES + tuple(
            _random_below(2, n - 2) for _ in range(_RANDOM_BASES)
        )

    for base in bases:
        value = pow(base, d, n)
        if value == 1 or value == n - 1:
            continue
        for _ in range(power - 1):
            value = value * value % n
            if value == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    """Return a random prime of exactly ``bits`` bits.

    The top two bits are set on purpose. A product of two primes that each
    carry their two most significant bits is guaranteed to have the full
    ``2 * bits`` bit length, so :func:`generate_key_pair` does not have to
    retry a modulus that came back a bit short.
    """

    if bits < 2:
        raise ValueError("a prime needs at least two bits")
    while True:
        candidate = _random_below(1 << (bits - 1), 1 << bits)
        candidate |= 3 << (bits - 2)
        candidate |= 1
        if _is_probable_prime(candidate):
            return candidate


def generate_key_pair(bits: int = 2048) -> tuple[RSAPublicKey, RSAPrivateKey]:
    """Return a fresh ``(public, private)`` pair with an ``n`` of ``bits`` bits.

    The two primes are independent draws of half the width each. A modulus whose
    factors are close is factorable by Fermat's method in about
    ``(p - q)**2 / (4 * sqrt(n))`` steps, so the difference is required to be
    larger than ``2**(bits/2 - 100)`` -- far below the typical gap between two
    random primes, but enough to exclude the pathological near-equal pair.

    The public exponent is the conventional 65537. It is coprime to ``phi``
    except for the negligible chance that a prime is congruent to 1 modulo it,
    in which case a fresh pair is drawn.
    """

    if not isinstance(bits, int) or isinstance(bits, bool):
        raise ValueError("the bit length must be an integer")
    if bits < 512 or bits % 8:
        raise ValueError("the bit length must be a multiple of 8 and at least 512")

    e = RSA_PUBLIC_EXPONENT
    half = bits // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(bits - half)
        if p == q:
            continue
        if abs(p - q) <= 1 << (half - 100):
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) != 1:
            continue
        d = pow(e, -1, phi)
        return (
            RSAPublicKey(n, e),
            RSAPrivateKey(n, e, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p)),
        )


# ---------------------------------------------------------------------------
# The RSA primitives.
# ---------------------------------------------------------------------------


def rsaep(public_key: RSAPublicKey, m: int) -> int:
    """Return the RSA encryption primitive ``m**e mod n``.

    The representative must already be in ``[0, n)``; a caller with a byte
    string uses :func:`encrypt`, which builds the OAEP block first.
    """

    if not 0 <= m < public_key.n:
        raise ValueError("the message representative must be in [0, n)")
    return pow(m, public_key.e, public_key.n)


def rsadp(private_key: RSAPrivateKey, c: int) -> int:
    """Return the RSA decryption primitive ``c**d mod n``, via the CRT.

    The exponentiation is split into ``m1 = c**dp mod p`` and ``m2 = c**dq mod
    q``, which are then recombined with Garner's formula:

        h = qinv * (m1 - m2) mod p
        m = m2 + h * q

    The result is re-encrypted and compared to ``c`` before it is returned. A
    fault anywhere in the CRT path produces an ``m`` that does not satisfy
    ``m**e == c mod n``, so the corruption is turned into a
    :class:`DecryptionError` rather than handed back as a plausible plaintext.
    """

    n = private_key.n
    if not 0 <= c < n:
        raise DecryptionError("the ciphertext representative is out of range")
    m1 = pow(c, private_key.dp, private_key.p)
    m2 = pow(c, private_key.dq, private_key.q)
    h = private_key.qinv * (m1 - m2) % private_key.p
    m = m2 + h * private_key.q
    if pow(m, private_key.e, n) != c:
        raise DecryptionError("the CRT result does not re-encrypt to the ciphertext")
    return m


# ---------------------------------------------------------------------------
# OAEP, the padding of PKCS #1 section 7.1.
# ---------------------------------------------------------------------------


def mgf1(seed: bytes, length: int) -> bytes:
    """Return the MGF1 mask of ``length`` bytes derived from ``seed``.

    The mask is the concatenation of ``SHA-256(seed || counter)`` for the
    counter starting at zero, truncated to ``length``. The counter is a 32-bit
    big-endian integer, which bounds the output at ``2**32`` hash blocks; a
    request past that is rejected rather than silently wrapped.
    """

    if length < 0:
        raise ValueError("the mask length cannot be negative")
    if length > 0xFFFFFFFF * OAEP_HASH_LENGTH:
        raise ValueError("the mask length is too large for a 32-bit counter")
    if not isinstance(seed, (bytes, bytearray, memoryview)):
        raise ValueError("the seed must be a bytes-like object")
    seed = bytes(seed)
    blocks = []
    counter = 0
    while len(blocks) * OAEP_HASH_LENGTH < length:
        blocks.append(sha256(seed + counter.to_bytes(4, "big")))
        counter += 1
    return b"".join(blocks)[:length]


def _xor(left: bytes, right: bytes) -> bytes:
    """Return ``left`` XOR ``right``; the two must be the same length."""

    if len(left) != len(right):
        raise ValueError("the operands must be the same length")
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def oaep_encode(message: bytes, k: int, label: bytes = b"") -> bytes:
    """Return the ``k``-byte OAEP encoding of ``message``.

    The block is ``0x00 || masked_seed || masked_db`` with

        DB = lHash || PS || 0x01 || M
        lHash = SHA-256(label)
        PS = k - mLen - 2*hLen - 2 zero bytes
        maskedDB = DB XOR MGF1(seed, k - hLen - 1)
        maskedSeed = seed XOR MGF1(maskedDB, hLen)

    and ``seed`` a fresh ``hLen``-byte draw from ``os.urandom``. The leading
    zero byte is what keeps the encoded message below the modulus, and the
    ``0x01`` is the separator that makes the start of the message unambiguous.
    """

    hlen = OAEP_HASH_LENGTH
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise ValueError("the message must be a bytes-like object")
    if not isinstance(label, (bytes, bytearray, memoryview)):
        raise ValueError("the label must be a bytes-like object")
    message = bytes(message)
    label = bytes(label)
    if k < 2 * hlen + 2:
        raise ValueError("the modulus is too short for OAEP with SHA-256")
    if len(message) > k - 2 * hlen - 2:
        raise ValueError("the message is too long for OAEP with this modulus")

    lhash = sha256(label)
    padding = b"\x00" * (k - len(message) - 2 * hlen - 2)
    db = lhash + padding + b"\x01" + message
    seed = os.urandom(hlen)
    masked_db = _xor(db, mgf1(seed, k - hlen - 1))
    masked_seed = _xor(seed, mgf1(masked_db, hlen))
    return b"\x00" + masked_seed + masked_db


def oaep_decode(encoded: bytes, k: int, label: bytes = b"") -> bytes:
    """Return the message inside a ``k``-byte OAEP block, or raise.

    Decoding undoes the two masks, then checks that the leading byte is zero,
    that the label hash matches, and that the padding is a run of zero bytes
    terminated by ``0x01``. Every condition is accumulated into a single verdict
    and a single :class:`DecryptionError`, so a caller cannot learn which check
    failed -- the property that keeps this decoder from being an oracle.
    """

    hlen = OAEP_HASH_LENGTH
    if not isinstance(encoded, (bytes, bytearray, memoryview)):
        raise ValueError("the encoded message must be a bytes-like object")
    if not isinstance(label, (bytes, bytearray, memoryview)):
        raise ValueError("the label must be a bytes-like object")
    encoded = bytes(encoded)
    label = bytes(label)
    if len(encoded) != k:
        raise DecryptionError("the encoded message is not the modulus length")
    if k < 2 * hlen + 2:
        raise DecryptionError("the modulus is too short for OAEP with SHA-256")

    lhash = sha256(label)
    masked_seed = encoded[1:1 + hlen]
    masked_db = encoded[1 + hlen:]
    seed = _xor(masked_seed, mgf1(masked_db, hlen))
    db = _xor(masked_db, mgf1(seed, k - hlen - 1))

    # Fold the three checks into one accumulator. The leading byte must be zero,
    # the recovered label hash must match, and PS must end in a 0x01 separator.
    bad = encoded[0]
    difference = 0
    for left, right in zip(db[:hlen], lhash, strict=True):
        difference |= left ^ right
    bad |= difference

    # The separator is the first non-zero byte after the label hash. The whole
    # region is scanned rather than stopping early, so the work done does not
    # depend on where the separator sits.
    index = 0
    found = 0
    for i in range(hlen, len(db)):
        if db[i] != 0 and not found:
            found = 1
            index = i
    if not found:
        bad |= 1
    else:
        bad |= db[index] ^ 0x01

    if bad:
        raise DecryptionError("the OAEP block does not decode")
    return db[index + 1:]


# ---------------------------------------------------------------------------
# The public interface, as frozen in INTERFACES.md.
# ---------------------------------------------------------------------------


def encrypt(public_key: RSAPublicKey, message: bytes, label: bytes = b"") -> bytes:
    """Return the OAEP ciphertext of ``message`` under ``public_key``.

    The message must fit in ``k - 2*hLen - 2`` bytes. A longer one raises
    ``ValueError`` rather than being truncated: a truncation would encrypt a
    different message than the caller passed and report success.
    """

    k = public_key.size_bytes()
    if len(message) > k - 2 * OAEP_HASH_LENGTH - 2:
        raise ValueError("the message is too long for OAEP with this modulus")
    encoded = oaep_encode(message, k, label)
    ciphertext = rsaep(public_key, int.from_bytes(encoded, "big"))
    return ciphertext.to_bytes(k, "big")


def decrypt(private_key: RSAPrivateKey, ciphertext: bytes, label: bytes = b"") -> bytes:
    """Return the message inside ``ciphertext``, or raise :class:`DecryptionError`.

    A ciphertext that is not exactly ``k`` bytes, that reads as a representative
    at or above ``n``, or whose OAEP block does not decode is refused with the
    same exception, so the refusal carries no information beyond "this did not
    decrypt".
    """

    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise ValueError("the ciphertext must be a bytes-like object")
    ciphertext = bytes(ciphertext)
    k = (private_key.n.bit_length() + 7) // 8
    if len(ciphertext) != k:
        raise DecryptionError("the ciphertext is not the modulus length")
    representative = int.from_bytes(ciphertext, "big")
    if not 0 <= representative < private_key.n:
        raise DecryptionError("the ciphertext representative is out of range")
    encoded = rsadp(private_key, representative).to_bytes(k, "big")
    return oaep_decode(encoded, k, label)
