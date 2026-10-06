"""ML-KEM, the module-lattice key-encapsulation mechanism of FIPS 203.

This is the post-quantum half of the toolkit. It is here because the arithmetic
is visible: the ring, the number-theoretic transform, the compression and the
implicit-rejection transform are all written out, and the whole thing is checked
against NIST's own ACVP vectors rather than against a description of them.

Everything here is built on `src/keccak.py`, which is built on nothing. No
third-party package is imported, and there is no reference implementation of
ML-KEM in the Python ecosystem to compare against, so the published vectors are
the entire external check. That makes them more load-bearing here than anywhere
else in this repository, which is why the vendored subset is exercised for all
three functions and all three parameter sets.

The parameter sets are the standard's. `MLKEM_TOY` is not: it is a reduced set
that exists so the benchmark can show what the lattice dimension costs, and it
is neither secure nor standard.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .keccak import sha3_256, sha3_512, shake_128, shake_256

__all__ = [
    "MLKEM_Q", "MLKEM_N", "MLKEM_SYMBYTES",
    "MLKEMParameters", "MLKEM_512", "MLKEM_768", "MLKEM_1024", "MLKEM_TOY",
    "MLKEM_PARAMETER_SETS",
    "keygen", "encapsulate", "decapsulate",
    "generate_key_pair", "encapsulate_random",
    "encapsulation_key_is_valid", "decapsulation_key_is_valid",
]

MLKEM_Q = 3329                 # FIPS 203: q is always 3329
MLKEM_N = 256                  # and n is always 256
MLKEM_SYMBYTES = 32            # d, z, m, the hash outputs and K are all 32 bytes

# 17 is a primitive 256th root of unity modulo q, which is what makes the
# transform of Section 4.3 an isomorphism rather than a change of basis.
_ZETA = 17
# NTT^-1 scales by 128^-1 mod q at the end (Algorithm 10, step 14).
_NTT_INVERSE_SCALE = 3303


@dataclass(frozen=True)
class MLKEMParameters:
    """One row of Table 2 of FIPS 203, plus the security category of Section 8."""

    name: str
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int
    security_category: int

    @property
    def encapsulation_key_bytes(self) -> int:
        return 384 * self.k + 32

    @property
    def decapsulation_key_bytes(self) -> int:
        return 768 * self.k + 96

    @property
    def ciphertext_bytes(self) -> int:
        return 32 * (self.du * self.k + self.dv)

    @property
    def shared_secret_bytes(self) -> int:
        return 32

    @property
    def is_standard(self) -> bool:
        """False for the toy set, so callers can refuse to use it."""
        return self.security_category > 0


MLKEM_512 = MLKEMParameters("ML-KEM-512", 2, 3, 2, 10, 4, 1)
MLKEM_768 = MLKEMParameters("ML-KEM-768", 3, 2, 2, 10, 4, 3)
MLKEM_1024 = MLKEMParameters("ML-KEM-1024", 4, 2, 2, 11, 5, 5)

# k = 1 with the ML-KEM-512 noise and compression parameters. No standard
# defines this, it is not secure, and security_category is 0 to say so.
MLKEM_TOY = MLKEMParameters("ML-KEM-toy", 1, 2, 2, 10, 4, 0)

MLKEM_PARAMETER_SETS = (MLKEM_512, MLKEM_768, MLKEM_1024)


def _bit_reverse_7(value: int) -> int:
    """BitRev7 of FIPS 203 Section 4.3: reverse the seven bits of a small integer."""
    result = 0
    for _ in range(7):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


def _ntt_twiddles() -> tuple[int, ...]:
    """zeta^BitRev7(i) mod q for i in 0..127: the NTT's own twiddle factors."""
    return tuple(pow(_ZETA, _bit_reverse_7(i), MLKEM_Q) for i in range(128))


def _multiply_twiddles() -> tuple[int, ...]:
    """zeta^(2*BitRev7(i)+1) mod q for i in 0..127: the moduli of the 128
    quadratic extensions, which Algorithm 11 uses as the gamma of each
    BaseCaseMultiply. This is a different table from the NTT's -- the exponent
    doubles and gains one, so it ranges over the odd powers -- and using the
    NTT's table here is a mistake that produces a plausible-looking wrong
    answer rather than an error, because every entry is still a valid element
    of the field.
    """
    return tuple(pow(_ZETA, 2 * _bit_reverse_7(i) + 1, MLKEM_Q) for i in range(128))


_ZETAS = _ntt_twiddles()
_MULTIPLY_GAMMAS = _multiply_twiddles()


def _ntt(coefficients: list[int]) -> list[int]:
    """Algorithm 9 of FIPS 203, in place on a copy."""
    f = list(coefficients)
    index = 1
    length = 128
    while length >= 2:
        start = 0
        while start < MLKEM_N:
            zeta = _ZETAS[index]
            index += 1
            for j in range(start, start + length):
                t = zeta * f[j + length] % MLKEM_Q
                f[j + length] = (f[j] - t) % MLKEM_Q
                f[j] = (f[j] + t) % MLKEM_Q
            start += 2 * length
        length //= 2
    return f


def _ntt_inverse(coefficients: list[int]) -> list[int]:
    """Algorithm 10 of FIPS 203. Note the twiddles run backwards and there is a
    final scaling by 128^-1, which is the step that is easy to leave out and
    which then shows up only as a wrong shared secret."""
    f = list(coefficients)
    index = 127
    length = 2
    while length <= 128:
        start = 0
        while start < MLKEM_N:
            zeta = _ZETAS[index]
            index -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % MLKEM_Q
                f[j + length] = zeta * (f[j + length] - t) % MLKEM_Q
            start += 2 * length
        length *= 2
    return [value * _NTT_INVERSE_SCALE % MLKEM_Q for value in f]


def _base_case_multiply(a0: int, a1: int, b0: int, b1: int, gamma: int) -> tuple[int, int]:
    """Algorithm 12: multiplication in one quadratic extension of Z_q."""
    return ((a0 * b0 + a1 * b1 % MLKEM_Q * gamma) % MLKEM_Q,
            (a0 * b1 + a1 * b0) % MLKEM_Q)


def _multiply_ntts(f: list[int], g: list[int]) -> list[int]:
    """Algorithm 11: the product in the NTT domain, one quadratic extension at a time."""
    h = [0] * MLKEM_N
    for i in range(128):
        h[2 * i], h[2 * i + 1] = _base_case_multiply(
            f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1], _MULTIPLY_GAMMAS[i])
    return h


def _compress(value: int, d: int) -> int:
    """Compress_d of FIPS 203 Section 4.2.1: round(2^d/q * x) mod 2^d.

    The standard forbids floating point here, and q is odd, so an exact integer
    round-half-up is the same thing and cannot tie.
    """
    return ((value << d) + MLKEM_Q // 2) // MLKEM_Q % (1 << d)


def _decompress(value: int, d: int) -> int:
    """Decompress_d: round(q/2^d * y)."""
    return (MLKEM_Q * value + (1 << (d - 1))) >> d


def _byte_encode(coefficients: list[int], d: int) -> bytes:
    """Algorithm 5: pack 256 d-bit values into a little-endian bit stream.

    Bits fill each byte from the least significant end, which is what
    BitsToBytes means in the standard and is not the same as packing integers
    big-endian into fixed-width fields.
    """
    out = bytearray()
    accumulator = 0
    bits = 0
    for value in coefficients:
        accumulator |= (value & ((1 << d) - 1)) << bits
        bits += d
        while bits >= 8:
            out.append(accumulator & 0xFF)
            accumulator >>= 8
            bits -= 8
    if bits:
        out.append(accumulator & 0xFF)
    return bytes(out)


def _byte_decode(data: bytes, d: int) -> list[int]:
    """Algorithm 6: the inverse of _byte_encode.

    For d = 12 this is deliberately *not* a true inverse. The standard says
    ByteDecode12 reads each 12-bit segment as an integer modulo 4096 and then
    reduces it modulo q, so a segment holding a value in [q, 4096) decodes to
    something smaller than it was encoded from. That asymmetry is the whole
    mechanism of the encapsulation-key modulus check in Section 7.2: it is what
    makes a key with an out-of-range coefficient fail to round trip. Decoding
    without the reduction makes every key look valid, and the K-PKE paths hide
    the mistake because they reduce mod q again immediately afterwards.
    """
    out = []
    accumulator = 0
    bits = 0
    for byte in data:
        accumulator |= byte << bits
        bits += 8
        while bits >= d:
            value = accumulator & ((1 << d) - 1)
            out.append(value % MLKEM_Q if d == 12 else value)
            accumulator >>= d
            bits -= d
    return out


def _sample_ntt(seed: bytes) -> list[int]:
    """Algorithm 7 SampleNTT: rejection-sample a uniform element of T_q.

    The standard pulls three bytes at a time from an incremental SHAKE128. A
    single SHAKE128 call of the full length produces the same stream -- FIPS 203
    Section 4.1 says so explicitly -- so this squeezes a block and walks it,
    growing the block if the rejection rate is unusually unkind. The loop bound
    is the one Appendix B discusses; doubling is a far looser bound than the
    standard's and costs nothing because it is never reached.
    """
    if len(seed) != 34:
        raise ValueError(f"SampleNTT takes 34 bytes (a 32-byte seed and two indices), not {len(seed)}")

    wanted = 3 * MLKEM_N          # enough for the overwhelming majority of seeds
    while True:
        stream = shake_128(seed, wanted)
        out = [0] * MLKEM_N
        j = 0
        for offset in range(0, len(stream) - 2, 3):
            c0, c1, c2 = stream[offset], stream[offset + 1], stream[offset + 2]
            d1 = c0 + 256 * (c1 % 16)
            d2 = (c1 // 16) + 16 * c2
            if d1 < MLKEM_Q:
                out[j] = d1
                j += 1
            if j < MLKEM_N and d2 < MLKEM_Q:
                out[j] = d2
                j += 1
            if j >= MLKEM_N:
                return out
        wanted *= 2


def _sample_poly_cbd(eta: int, data: bytes) -> list[int]:
    """Algorithm 8 SamplePolyCBD: coefficients are differences of two bit counts."""
    if len(data) != 64 * eta:
        raise ValueError(f"CBD with eta={eta} takes {64 * eta} bytes, not {len(data)}")
    bits = [(byte >> i) & 1 for byte in data for i in range(8)]
    coefficients = []
    for i in range(MLKEM_N):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        coefficients.append((x - y) % MLKEM_Q)
    return coefficients


def _prf(eta: int, seed: bytes, counter: int) -> bytes:
    """PRF_eta(s, b) = SHAKE256(s || b, 64*eta), FIPS 203 equation (4.3)."""
    return shake_256(seed + bytes([counter]), 64 * eta)


def _h(data: bytes) -> bytes:
    """H = SHA3-256, FIPS 203 equation (4.4)."""
    return sha3_256(data)


def _j(data: bytes) -> bytes:
    """J = SHAKE256(s, 32), FIPS 203 equation (4.4)."""
    return shake_256(data, 32)


def _g(data: bytes) -> tuple[bytes, bytes]:
    """G = SHA3-512, split into two 32-byte halves, FIPS 203 equation (4.5)."""
    digest = sha3_512(data)
    return digest[:32], digest[32:]


def _sample_matrix(rho: bytes, k: int) -> list[list[list[int]]]:
    """A[i][j] = SampleNTT(rho || j || i).

    The index order is j then i, which is the opposite of the reading order and
    is the one thing in Algorithm 13 that is easy to swap. Getting it wrong
    still produces a self-consistent key pair, so only the published vectors
    catch it.
    """
    return [[_sample_ntt(rho + bytes([j, i])) for j in range(k)] for i in range(k)]


def _matrix_vector_product(matrix: list[list[list[int]]], vector: list[list[int]],
                           transpose: bool) -> list[list[int]]:
    """The NTT-domain matrix-vector product of FIPS 203 Section 2.4.7."""
    k = len(vector)
    result = []
    for i in range(k):
        accumulator = [0] * MLKEM_N
        for j in range(k):
            entry = matrix[j][i] if transpose else matrix[i][j]
            product = _multiply_ntts(entry, vector[j])
            accumulator = [(a + b) % MLKEM_Q for a, b in zip(accumulator, product)]
        result.append(accumulator)
    return result


def _vector_inner_product(a: list[list[int]], b: list[list[int]]) -> list[int]:
    accumulator = [0] * MLKEM_N
    for left, right in zip(a, b):
        product = _multiply_ntts(left, right)
        accumulator = [(x + y) % MLKEM_Q for x, y in zip(accumulator, product)]
    return accumulator


def _kpke_keygen(d: bytes, parameters: MLKEMParameters) -> tuple[bytes, bytes]:
    """Algorithm 13 K-PKE.KeyGen."""
    k = parameters.k
    rho, sigma = _g(d + bytes([k]))
    matrix = _sample_matrix(rho, k)

    counter = 0
    s = []
    for _ in range(k):
        s.append(_sample_poly_cbd(parameters.eta1, _prf(parameters.eta1, sigma, counter)))
        counter += 1
    e = []
    for _ in range(k):
        e.append(_sample_poly_cbd(parameters.eta1, _prf(parameters.eta1, sigma, counter)))
        counter += 1

    s_hat = [_ntt(poly) for poly in s]
    e_hat = [_ntt(poly) for poly in e]

    t_hat = []
    for i in range(k):
        accumulator = [0] * MLKEM_N
        for j in range(k):
            product = _multiply_ntts(matrix[i][j], s_hat[j])
            accumulator = [(a + b) % MLKEM_Q for a, b in zip(accumulator, product)]
        t_hat.append([(a + b) % MLKEM_Q for a, b in zip(accumulator, e_hat[i])])

    encryption_key = b"".join(_byte_encode(poly, 12) for poly in t_hat) + rho
    decryption_key = b"".join(_byte_encode(poly, 12) for poly in s_hat)
    return encryption_key, decryption_key


def _kpke_encrypt(encryption_key: bytes, message: bytes, randomness: bytes,
                  parameters: MLKEMParameters) -> bytes:
    """Algorithm 14 K-PKE.Encrypt."""
    k = parameters.k
    t_hat = [_byte_decode(encryption_key[384 * i:384 * i + 384], 12) for i in range(k)]
    t_hat = [[value % MLKEM_Q for value in poly] for poly in t_hat]
    rho = encryption_key[384 * k:384 * k + 32]
    matrix = _sample_matrix(rho, k)

    counter = 0
    y = []
    for _ in range(k):
        y.append(_sample_poly_cbd(parameters.eta1, _prf(parameters.eta1, randomness, counter)))
        counter += 1
    e1 = []
    for _ in range(k):
        e1.append(_sample_poly_cbd(parameters.eta2, _prf(parameters.eta2, randomness, counter)))
        counter += 1
    e2 = _sample_poly_cbd(parameters.eta2, _prf(parameters.eta2, randomness, counter))

    y_hat = [_ntt(poly) for poly in y]

    u = []
    for poly in _matrix_vector_product(matrix, y_hat, transpose=True):
        u.append([(a + b) % MLKEM_Q for a, b in zip(_ntt_inverse(poly), e1[len(u)])])

    mu = [_decompress(value, 1) for value in _byte_decode(message, 1)]
    v = _ntt_inverse(_vector_inner_product(t_hat, y_hat))
    v = [(a + b + c) % MLKEM_Q for a, b, c in zip(v, e2, mu)]

    c1 = b"".join(_byte_encode([_compress(value, parameters.du) for value in poly], parameters.du)
                  for poly in u)
    c2 = _byte_encode([_compress(value, parameters.dv) for value in v], parameters.dv)
    return c1 + c2


def _kpke_decrypt(decryption_key: bytes, ciphertext: bytes,
                  parameters: MLKEMParameters) -> bytes:
    """Algorithm 15 K-PKE.Decrypt."""
    k = parameters.k
    split = 32 * parameters.du * k
    c1, c2 = ciphertext[:split], ciphertext[split:]

    u = [[value % MLKEM_Q for value in _byte_decode(c1[32 * parameters.du * i:
                                                      32 * parameters.du * (i + 1)], parameters.du)]
         for i in range(k)]
    u = [[_decompress(value, parameters.du) for value in poly] for poly in u]
    v = [_decompress(value, parameters.dv) for value in _byte_decode(c2, parameters.dv)]

    s_hat = [[value % MLKEM_Q for value in _byte_decode(decryption_key[384 * i:384 * i + 384], 12)]
             for i in range(k)]

    u_hat = [_ntt(poly) for poly in u]
    w = _ntt_inverse(_vector_inner_product(s_hat, u_hat))
    w = [(a - b) % MLKEM_Q for a, b in zip(v, w)]
    return _byte_encode([_compress(value, 1) for value in w], 1)


def keygen(d: bytes, z: bytes, parameters: MLKEMParameters = MLKEM_768) -> tuple[bytes, bytes]:
    """Algorithm 16, ML-KEM.KeyGen_internal. Deterministic: `d` and `z` are the
    randomness, which is the only way the published vectors can be checked."""
    if len(d) != MLKEM_SYMBYTES or len(z) != MLKEM_SYMBYTES:
        raise ValueError("d and z are each 32 bytes")
    encryption_key, decryption_key = _kpke_keygen(d, parameters)
    return encryption_key, decryption_key + encryption_key + _h(encryption_key) + z


def encapsulate(encryption_key: bytes, message: bytes,
                parameters: MLKEMParameters = MLKEM_768) -> tuple[bytes, bytes]:
    """Algorithm 17, ML-KEM.Encaps_internal. Returns (shared_secret, ciphertext)."""
    if len(message) != MLKEM_SYMBYTES:
        raise ValueError("the encapsulation randomness m is 32 bytes")
    shared_secret, randomness = _g(message + _h(encryption_key))
    return shared_secret, _kpke_encrypt(encryption_key, message, randomness, parameters)


def decapsulate(decapsulation_key: bytes, ciphertext: bytes,
                parameters: MLKEMParameters = MLKEM_768) -> bytes:
    """Algorithm 18, ML-KEM.Decaps_internal.

    Total by design: a ciphertext that does not re-encrypt to itself yields the
    implicit-rejection secret J(z || c) rather than an error. Raising instead
    would answer the question "was this ciphertext well formed", which is
    exactly the oracle the transform exists to deny.
    """
    k = parameters.k
    decryption_key = decapsulation_key[:384 * k]
    encryption_key = decapsulation_key[384 * k:768 * k + 32]
    h = decapsulation_key[768 * k + 32:768 * k + 64]
    z = decapsulation_key[768 * k + 64:768 * k + 96]

    message = _kpke_decrypt(decryption_key, ciphertext, parameters)
    shared_secret, randomness = _g(message + h)
    rejected = _j(z + ciphertext)
    if _kpke_encrypt(encryption_key, message, randomness, parameters) != ciphertext:
        shared_secret = rejected
    return shared_secret


def generate_key_pair(parameters: MLKEMParameters = MLKEM_768) -> tuple[bytes, bytes]:
    """ML-KEM.KeyGen: the internal key generation with fresh randomness."""
    return keygen(os.urandom(MLKEM_SYMBYTES), os.urandom(MLKEM_SYMBYTES), parameters)


def encapsulate_random(encryption_key: bytes,
                       parameters: MLKEMParameters = MLKEM_768) -> tuple[bytes, bytes]:
    """ML-KEM.Encaps: encapsulation with fresh randomness. Returns (K, c)."""
    return encapsulate(encryption_key, os.urandom(MLKEM_SYMBYTES), parameters)


def encapsulation_key_is_valid(encryption_key: bytes,
                               parameters: MLKEMParameters = MLKEM_768) -> bool:
    """The two checks of FIPS 203 Section 7.2: length, then every coefficient in range.

    The modulus check is the round trip through ByteDecode12 and ByteEncode12:
    a 12-bit field can hold a value above q - 1, so an encoding that survives the
    round trip is one whose coefficients were all already reduced.
    """
    if len(encryption_key) != parameters.encapsulation_key_bytes:
        return False
    body = encryption_key[:384 * parameters.k]
    return _byte_encode(_byte_decode(body, 12), 12) == body


def decapsulation_key_is_valid(decapsulation_key: bytes,
                               parameters: MLKEMParameters = MLKEM_768) -> bool:
    """The two checks of FIPS 203 Section 7.3: length, then the embedded hash.

    A decapsulation key carries H(ek) so that the pair can be checked without
    re-deriving the key from its seed.
    """
    k = parameters.k
    if len(decapsulation_key) != parameters.decapsulation_key_bytes:
        return False
    encryption_key = decapsulation_key[384 * k:768 * k + 32]
    embedded = decapsulation_key[768 * k + 32:768 * k + 64]
    return _h(encryption_key) == embedded
