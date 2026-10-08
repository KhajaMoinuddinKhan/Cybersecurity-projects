"""AES-128/192/256 and counter mode, written out from the primitives up.

Nothing in this module calls a cryptographic library.  The S-box is derived from
the multiplicative inverse in GF(2**8) rather than pasted in as 256 constants,
the key schedule is the FIPS-197 expansion, and each round is spelled out as
SubBytes, ShiftRows, MixColumns and AddRoundKey (with the inverse of each for
decryption).  A reader should be able to follow a single plaintext byte from the
S-box to the ciphertext without leaving this file.

The AES state is a 4x4 array of bytes.  We keep it flat and column-major, so
``state[4 * column + row]`` is the byte at (row, column).  A 16-byte block maps
onto the state in its natural order, which is also the order the round keys are
produced in, so AddRoundKey is a plain byte-wise XOR.
"""

from __future__ import annotations

AES_BLOCK_SIZE = 16

# ---------------------------------------------------------------------------
# Arithmetic in GF(2**8) and the S-box
# ---------------------------------------------------------------------------
# AES treats a byte as an element of GF(2**8) reduced modulo the polynomial
# x**8 + x**4 + x**3 + x + 1 (0x11b, with the high bit implied).  The S-box is
# not an arbitrary lookup table: it is the multiplicative inverse of a byte in
# that field, followed by a fixed affine transform over the bits.  We compute it
# here because the computation is the whole point.  A literal table would give
# the same 256 values; we deliberately do the field arithmetic instead.

_GF_REDUCE = 0x11B  # x**8 + x**4 + x**3 + x + 1, low eight bits


def _gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2**8) modulo the AES polynomial.

    Schoolbook "carry-less" multiplication: shift and XOR, reducing whenever the
    running product overflows the eighth bit.
    """
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= _GF_REDUCE & 0xFF
        b >>= 1
    return product


def _gf_inverse(a: int) -> int:
    """Return the multiplicative inverse of ``a`` in GF(2**8).

    Every non-zero element has one, and in a field of size 2**8 it is simply
    ``a ** 254``.  The inverse of zero is defined to be zero, which is what the
    affine transform below expects.
    """
    if a == 0:
        return 0
    result = 1
    power = a
    exponent = 254  # 2**8 - 2
    while exponent:
        if exponent & 1:
            result = _gf_mul(result, power)
        power = _gf_mul(power, power)
        exponent >>= 1
    return result


def _affine_transform(b: int) -> int:
    """The bit-mixing step of the S-box.

    Each output bit is the XOR of the input bit and four of its neighbours,
    rotated, with the constant 0x63 folded in.  That is exactly
    ``b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4) ^ 0x63``.
    """
    s = b
    for shift in range(1, 5):
        s ^= ((b << shift) | (b >> (8 - shift))) & 0xFF
    return s ^ 0x63


S_BOX = tuple(_affine_transform(_gf_inverse(x)) for x in range(256))

_inverse_box = [0] * 256
for _i, _value in enumerate(S_BOX):
    _inverse_box[_value] = _i
INV_S_BOX = tuple(_inverse_box)

# Round constants for the key schedule: 2**(i-1) in GF(2**8), one per expansion
# step that wraps.  Ten entries cover AES-128 (which needs ten) and then some.
R_CON = (
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
)


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------
# The contract is that malformed input raises ValueError - never IndexError or
# a struct error - so every entry point funnels through these.

def _require_bytes(value, name):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise ValueError(f"{name} must be a bytes-like object")


def _counter_value(initial_counter_block: bytes) -> int:
    """Validate a 16-byte counter block and return it as a big-endian integer."""
    block = _require_bytes(initial_counter_block, "initial counter block")
    if len(block) != AES_BLOCK_SIZE:
        raise ValueError(
            "the initial counter block must be exactly "
            f"{AES_BLOCK_SIZE} bytes, got {len(block)}"
        )
    return int.from_bytes(block, "big")


# ---------------------------------------------------------------------------
# Key expansion
# ---------------------------------------------------------------------------

def _expand_key(key: bytes):
    """Run the FIPS-197 key schedule.

    Returns ``(rounds, round_keys)`` where ``rounds`` is the number of cipher
    rounds and ``round_keys`` holds one 16-byte key per round plus the initial
    whitening key.  The number of rounds follows directly from the key size:
    AES-128 (4-word key) needs 10 rounds, AES-192 needs 12 and AES-256 needs 14.
    The schedule is what forces that - each round key is derived from the one
    before it, and a longer key simply buys more of them.
    """
    nk = len(key) // 4          # key length in 32-bit words: 4, 6 or 8
    rounds = nk + 6             # 10, 12 or 14

    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    total_words = 4 * (rounds + 1)
    for i in range(nk, total_words):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]                 # RotWord
            temp = [S_BOX[b] for b in temp]            # SubWord
            temp[0] ^= R_CON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [S_BOX[b] for b in temp]            # SubWord, AES-256 only
        words.append([a ^ b for a, b in zip(words[i - nk], temp, strict=False)])

    round_keys = []
    for r in range(rounds + 1):
        flat = bytes(byte for word in words[4 * r:4 * r + 4] for byte in word)
        round_keys.append(flat)
    return rounds, round_keys


# ---------------------------------------------------------------------------
# The four round operations and their inverses
# ---------------------------------------------------------------------------

def _add_round_key(state: bytearray, round_key: bytes) -> None:
    """XOR the round key into the state, in place."""
    for i in range(AES_BLOCK_SIZE):
        state[i] ^= round_key[i]


def _sub_bytes(state: bytearray) -> bytearray:
    """Replace every byte with its S-box entry (the non-linear step)."""
    return bytearray(S_BOX[b] for b in state)


def _inv_sub_bytes(state: bytearray) -> bytearray:
    """Undo SubBytes with the inverse S-box."""
    return bytearray(INV_S_BOX[b] for b in state)


def _shift_rows(state: bytearray) -> bytearray:
    """Rotate row r of the state left by r bytes.

    Row 0 is untouched, row 1 moves one column left, and so on.  With our flat
    column-major layout the byte at (row, column) lives at ``4*column + row``.
    """
    out = bytearray(AES_BLOCK_SIZE)
    for row in range(4):
        for column in range(4):
            out[4 * column + row] = state[4 * ((column + row) % 4) + row]
    return out


def _inv_shift_rows(state: bytearray) -> bytearray:
    """Rotate row r of the state right by r bytes - the inverse of ShiftRows."""
    out = bytearray(AES_BLOCK_SIZE)
    for row in range(4):
        for column in range(4):
            out[4 * column + row] = state[4 * ((column - row) % 4) + row]
    return out


def _mix_columns(state: bytearray) -> bytearray:
    """Mix each column with the fixed matrix [[2,3,1,1],[1,2,3,1],...].

    Multiplication is in GF(2**8), so this is a linear combination of the four
    bytes in a column; together with ShiftRows it spreads one changed byte
    across the whole state after a couple of rounds.
    """
    out = bytearray(AES_BLOCK_SIZE)
    for column in range(4):
        a0, a1, a2, a3 = state[4 * column:4 * column + 4]
        out[4 * column + 0] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        out[4 * column + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        out[4 * column + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        out[4 * column + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)
    return out


def _inv_mix_columns(state: bytearray) -> bytearray:
    """Undo MixColumns with the inverse matrix [[14,11,13,9],[9,14,11,13],...]."""
    out = bytearray(AES_BLOCK_SIZE)
    for column in range(4):
        a0, a1, a2, a3 = state[4 * column:4 * column + 4]
        out[4 * column + 0] = (
            _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9)
        )
        out[4 * column + 1] = (
            _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13)
        )
        out[4 * column + 2] = (
            _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11)
        )
        out[4 * column + 3] = (
            _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14)
        )
    return out


# ---------------------------------------------------------------------------
# The cipher
# ---------------------------------------------------------------------------

class AES:
    """The AES block cipher for 128-, 192- and 256-bit keys.

    Construct it with a key, then call :meth:`encrypt_block` /
    :meth:`decrypt_block` for single 16-byte blocks, or :meth:`encrypt` /
    :meth:`decrypt` to run ECB over a whole buffer.  ECB is exposed because it
    is the raw cipher and it is what the standard vectors exercise; it is not a
    safe mode on its own, which is why counter mode exists below.
    """

    def __init__(self, key: bytes) -> None:
        key = _require_bytes(key, "key")
        if len(key) not in (16, 24, 32):
            raise ValueError(
                "an AES key must be 16, 24 or 32 bytes "
                f"(AES-128/192/256), got {len(key)}"
            )
        self.key_size = len(key) * 8
        self._rounds, self._round_keys = _expand_key(key)

    # -- single block -------------------------------------------------------

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt one 16-byte block.

        The rounds are: an initial AddRoundKey, then ``rounds - 1`` full rounds
        of SubBytes, ShiftRows, MixColumns and AddRoundKey, and a final round
        that omits MixColumns.
        """
        block = _require_bytes(block, "block")
        if len(block) != AES_BLOCK_SIZE:
            raise ValueError(
                f"a block must be exactly {AES_BLOCK_SIZE} bytes, got {len(block)}"
            )

        state = bytearray(block)
        _add_round_key(state, self._round_keys[0])
        for r in range(1, self._rounds):
            state = _sub_bytes(state)
            state = _shift_rows(state)
            state = _mix_columns(state)
            _add_round_key(state, self._round_keys[r])
        state = _sub_bytes(state)
        state = _shift_rows(state)
        _add_round_key(state, self._round_keys[self._rounds])
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt one 16-byte block by running the rounds in reverse.

        Each step is the inverse of the encryption step, applied in the opposite
        order, starting from the last round key.
        """
        block = _require_bytes(block, "block")
        if len(block) != AES_BLOCK_SIZE:
            raise ValueError(
                f"a block must be exactly {AES_BLOCK_SIZE} bytes, got {len(block)}"
            )

        state = bytearray(block)
        _add_round_key(state, self._round_keys[self._rounds])
        for r in range(self._rounds - 1, 0, -1):
            state = _inv_shift_rows(state)
            state = _inv_sub_bytes(state)
            _add_round_key(state, self._round_keys[r])
            state = _inv_mix_columns(state)
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        _add_round_key(state, self._round_keys[0])
        return bytes(state)

    # -- ECB over a buffer --------------------------------------------------

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt a whole buffer in ECB mode; the length must be a multiple of 16."""
        data = _require_bytes(data, "data")
        if len(data) % AES_BLOCK_SIZE != 0:
            raise ValueError(
                f"data length must be a multiple of {AES_BLOCK_SIZE}, "
                f"got {len(data)}"
            )
        return b"".join(
            self.encrypt_block(data[i:i + AES_BLOCK_SIZE])
            for i in range(0, len(data), AES_BLOCK_SIZE)
        )

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt a whole ECB buffer; the length must be a multiple of 16."""
        data = _require_bytes(data, "data")
        if len(data) % AES_BLOCK_SIZE != 0:
            raise ValueError(
                f"data length must be a multiple of {AES_BLOCK_SIZE}, "
                f"got {len(data)}"
            )
        return b"".join(
            self.decrypt_block(data[i:i + AES_BLOCK_SIZE])
            for i in range(0, len(data), AES_BLOCK_SIZE)
        )


# ---------------------------------------------------------------------------
# Counter mode
# ---------------------------------------------------------------------------

def ctr_keystream(key: bytes, initial_counter_block: bytes, length: int) -> bytes:
    """Produce ``length`` bytes of AES-CTR keystream.

    The counter block is treated as a single big-endian 128-bit integer.  Each
    keystream block is the AES encryption of the current counter, after which
    the counter is incremented by one; on overflow it wraps back to zero rather
    than raising.  The caller XORs the result with the data (see
    :func:`xor_bytes`) - because CTR is a stream cipher, encryption and
    decryption are the same operation.
    """
    if isinstance(length, bool) or not isinstance(length, int):
        raise ValueError("length must be a non-negative integer")
    if length < 0:
        raise ValueError("length must be non-negative")

    aes = AES(key)
    counter = _counter_value(initial_counter_block)

    stream = bytearray()
    while len(stream) < length:
        stream += aes.encrypt_block(counter.to_bytes(AES_BLOCK_SIZE, "big"))
        counter = (counter + 1) % (1 << 128)
    return bytes(stream[:length])


class CTR:
    """Counter mode as a stream, so it can be applied to any length.

    The object remembers the counter and any keystream it has not consumed yet,
    so :meth:`update` may be called with data in whatever chunks the caller
    likes.  Decryption is just encryption again with the same key and counter
    block: ``CTR(key, block).update(ciphertext)`` recovers the plaintext.
    """

    def __init__(self, key: bytes, initial_counter_block: bytes) -> None:
        self._aes = AES(key)
        self._counter = _counter_value(initial_counter_block)
        self._buffer = b""

    def update(self, data: bytes) -> bytes:
        """XOR ``data`` with the next bytes of keystream, returning the result."""
        data = _require_bytes(data, "data")
        while len(self._buffer) < len(data):
            block = self._aes.encrypt_block(
                self._counter.to_bytes(AES_BLOCK_SIZE, "big")
            )
            self._buffer += block
            self._counter = (self._counter + 1) % (1 << 128)
        out = bytes(a ^ b for a, b in zip(data, self._buffer, strict=False))
        self._buffer = self._buffer[len(data):]
        return out


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two byte strings of equal length.

    Both arguments must have the same length; a mismatch means the caller has
    paired up the wrong buffers and is reported as a ``ValueError`` rather than
    silently truncated.  This is the combining step for CTR (keystream against
    data) and for the other modes built on top of AES.
    """
    left = _require_bytes(left, "left")
    right = _require_bytes(right, "right")
    if len(left) != len(right):
        raise ValueError(
            f"xor_bytes needs buffers of equal length, got {len(left)} and {len(right)}"
        )
    return bytes(a ^ b for a, b in zip(left, right, strict=False))
