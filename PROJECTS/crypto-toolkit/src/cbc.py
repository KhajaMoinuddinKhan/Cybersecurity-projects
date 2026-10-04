"""AES in cipher block chaining mode, with PKCS#7 padding.

The AES block cipher on its own is a fixed permutation of a single sixteen-byte
block: encrypt the same block twice and you get the same ciphertext, so an
attacker who guesses where a repeated field sits in a message can see the
repetition in the output.  CBC removes that by threading the blocks together.
Before a block goes through AES it is XORed with the previous *ciphertext*
block -- the initialization vector stands in for that on the very first block
-- and the block that comes out becomes the "previous" one for the next.  Each
ciphertext block therefore depends on every plaintext block that came before
it, and one changed byte in the plaintext changes the rest of the message
rather than only its own block.

The mode is defined on whole blocks and only whole blocks.  A message whose
length is not a multiple of sixteen has to be grown to one first, and PKCS#7
does that by appending N bytes of the value N.  N is at least one, so a message
that already lands on the block grid grows by a whole extra block instead of by
nothing -- which is the detail that makes the padding unambiguously removable.
If a full block of input could be padded with zero bytes, the last byte of a
message could never be trusted to say how much padding to strip.

Decryption runs AES backward on each block and XORs the previous ciphertext
block back in.  The raw form, :meth:`CBC.decrypt_blocks`, deliberately does no
unpadding: a caller who wants to inspect the padding bytes themselves -- a
padding oracle does exactly that -- needs them before they are validated away.
"""

from __future__ import annotations

from .aes import AES, xor_bytes

CBC_BLOCK_SIZE = 16


class PaddingError(ValueError):
    """The PKCS#7 padding on a decrypted block is not well formed.

    It subclasses ``ValueError`` because that is what every malformed argument
    in this project raises; the name exists so a caller can tell a bad *padding*
    apart from a bad *parameter* without parsing a message.
    """


def _require_bytes(value, name):
    """Return ``value`` as ``bytes``, or raise ``ValueError`` if it is not bytes-like.

    Funnelling every entry point through here is what keeps the contract that
    malformed input is a ``ValueError`` and never an ``IndexError`` or a
    ``TypeError`` from slicing the wrong thing.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise ValueError(f"{name} must be a bytes-like object")


def _require_block_size(block_size):
    """Validate a PKCS#7 block size and return it as an ``int``.

    PKCS#7 states the padding length in a single byte, so the largest block
    size it can describe is 255; anything outside ``1..255`` could not be
    encoded and is rejected up front rather than producing padding that cannot
    be read back.
    """
    if isinstance(block_size, bool) or not isinstance(block_size, int):
        raise ValueError("the block size must be an integer")
    if not 1 <= block_size <= 255:
        raise ValueError(
            f"the block size must be between 1 and 255, got {block_size}"
        )
    return block_size


def pkcs7_pad(data: bytes, block_size: int = CBC_BLOCK_SIZE) -> bytes:
    """Append PKCS#7 padding to ``data`` and return the padded bytes.

    The number of padding bytes is ``block_size - (len(data) % block_size)``.
    The modulo is the whole point: when ``data`` is already a multiple of the
    block size the remainder is zero, so the count comes out as a full block
    and a whole extra block of padding is added.  Padding is never zero bytes
    long, which is what lets the last byte of the padded message always state
    its own length unambiguously.
    """
    data = _require_bytes(data, "data")
    block_size = _require_block_size(block_size)

    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes, block_size: int = CBC_BLOCK_SIZE) -> bytes:
    """Remove PKCS#7 padding from ``data`` and return the message.

    The last byte of ``data`` is the claimed padding length.  It must be at
    least one and no larger than the block size, and the bytes it counts back
    must all carry that same value -- checking only the last byte would accept
    a message that was truncated and re-padded by an attacker.  Anything that
    fails one of those checks raises :class:`PaddingError`; so does data that is
    not a non-empty whole number of blocks, since there is then no padding to
    read.
    """
    data = _require_bytes(data, "data")
    block_size = _require_block_size(block_size)

    if len(data) == 0 or len(data) % block_size != 0:
        raise PaddingError(
            "padded data must be a non-empty whole number of blocks, "
            f"got {len(data)} bytes"
        )

    padding_length = data[-1]
    if padding_length == 0 or padding_length > block_size:
        raise PaddingError(
            f"the last byte claims {padding_length} padding bytes, which is "
            f"not a length between 1 and {block_size}"
        )
    expected = bytes([padding_length]) * padding_length
    if data[-padding_length:] != expected:
        raise PaddingError(
            "the trailing bytes do not all carry the claimed padding value"
        )
    return data[:-padding_length]


class CBC:
    """Cipher block chaining under one AES key.

    Construct it with a 16-, 24- or 32-byte key (the three AES key sizes;
    anything else raises ``ValueError``, which ``AES`` enforces).  :meth:`encrypt`
    and :meth:`decrypt` handle padding for you; :meth:`encrypt_blocks` and
    :meth:`decrypt_blocks` are the raw block-grid operations that do not.
    """

    def __init__(self, key: bytes) -> None:
        # AES validates the key length, so an invalid key is a ValueError from
        # here without this class repeating the check.
        self._aes = AES(key)

    @staticmethod
    def _require_iv(iv):
        """Return a validated 16-byte IV.

        The IV must be exactly one block: it is XORed with the first plaintext
        block, so a shorter or longer one could not line up with a block and
        the mode would not be CBC.
        """
        iv = _require_bytes(iv, "iv")
        if len(iv) != CBC_BLOCK_SIZE:
            raise ValueError(
                f"the IV must be exactly {CBC_BLOCK_SIZE} bytes, got {len(iv)}"
            )
        return iv

    def encrypt_blocks(self, iv: bytes, data: bytes) -> bytes:
        """Encrypt ``data`` with no padding; ``len(data)`` must be a multiple of 16.

        Each block is XORed with the previous ciphertext block -- the IV for
        the first one -- before it is run through AES, and the ciphertext that
        comes out becomes the "previous" block for the next.  That feedback is
        the entire mode.
        """
        previous = self._require_iv(iv)
        data = _require_bytes(data, "data")
        if len(data) % CBC_BLOCK_SIZE != 0:
            raise ValueError(
                f"data length must be a multiple of {CBC_BLOCK_SIZE}, "
                f"got {len(data)}"
            )

        out = bytearray()
        for offset in range(0, len(data), CBC_BLOCK_SIZE):
            block = data[offset:offset + CBC_BLOCK_SIZE]
            # Chain: mix in the previous ciphertext, then encipher.
            chained = xor_bytes(block, previous)
            previous = self._aes.encrypt_block(chained)
            out += previous
        return bytes(out)

    def decrypt_blocks(self, iv: bytes, data: bytes) -> bytes:
        """Decrypt ``data`` and return the raw bytes, padding included.

        AES decryption is applied to each block first and the previous
        *ciphertext* block is XORed back in afterwards -- the reverse of the
        encryption order, which is what makes the chain undo cleanly.  No
        unpadding happens here on purpose: the caller receives the padding
        bytes so it can decide for itself what they mean.
        """
        previous = self._require_iv(iv)
        data = _require_bytes(data, "data")
        if len(data) % CBC_BLOCK_SIZE != 0:
            raise ValueError(
                f"data length must be a multiple of {CBC_BLOCK_SIZE}, "
                f"got {len(data)}"
            )

        out = bytearray()
        for offset in range(0, len(data), CBC_BLOCK_SIZE):
            block = data[offset:offset + CBC_BLOCK_SIZE]
            decrypted = self._aes.decrypt_block(block)
            # Unchain: the block XORs with the ciphertext before it, not the
            # plaintext, so capture it before moving on.
            out += xor_bytes(decrypted, previous)
            previous = block
        return bytes(out)

    def encrypt(self, iv: bytes, plaintext: bytes) -> bytes:
        """Pad ``plaintext`` with PKCS#7, then encrypt it in CBC mode."""
        return self.encrypt_blocks(iv, pkcs7_pad(plaintext))

    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        """Decrypt ``ciphertext`` in CBC mode, then remove its PKCS#7 padding.

        Raises :class:`PaddingError` when the recovered padding is not valid,
        which is the signal a padding-oracle attack watches for.
        """
        return pkcs7_unpad(self.decrypt_blocks(iv, ciphertext))
