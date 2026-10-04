"""The padding oracle attack on AES-CBC with PKCS#7 padding.

CBC on its own hides a plaintext well. What breaks it is not the cipher but the
error message. PKCS#7 padding says the last N bytes are all the value N, and a
receiver that has to strip that padding has to decide whether it is valid -- and
if it tells the sender which way it decided, it has handed over an oracle.

The oracle answers one question: given a ciphertext, did it decrypt to valid
padding? That is one bit, and it is enough. CBC decrypts each block and then
XORs it with the previous ciphertext block, so the previous block is an input
the attacker controls. Flipping a byte of it flips the corresponding byte of the
plaintext, which means the attacker can drive the last byte of the plaintext
through all 256 values and watch for the one that produces valid padding. That
pins the byte down, and knowing it makes the *next* byte the last one, so the
whole block falls a byte at a time -- about 128 guesses per byte rather than
2**128 for the block.

Nothing here needs the key, and nothing here needs a wrong answer to be
distinguishable by anything other than its content: a different error string, a
different status code, or even a different response time is the same oracle.

The recovered plaintext is the plaintext *with its padding still on*, because
the padding is what the oracle is answering about and the attack genuinely
learns it. Strip it with ``src.cbc.pkcs7_unpad`` if you want the message.
"""
from __future__ import annotations

from ..cbc import CBC, CBC_BLOCK_SIZE, PaddingError, pkcs7_unpad


def padding_oracle(key: bytes, block_size: int = CBC_BLOCK_SIZE):
    """A real padding oracle over AES-CBC, written out so the attack has a target.

    This is the vulnerable behaviour rather than a description of it. It is what
    a server does when it answers "padding error" differently from "bad MAC", or
    when it takes a measurably different amount of time to do so.
    """

    cipher = CBC(key)

    def oracle(iv: bytes, block: bytes) -> bool:
        try:
            pkcs7_unpad(cipher.decrypt_blocks(iv, block), block_size)
        except PaddingError:
            return False
        return True

    return oracle


def recover_block(oracle, iv: bytes, block: bytes, block_size: int = CBC_BLOCK_SIZE) -> bytes:
    """Recover one block's plaintext, given the block that precedes it.

    ``iv`` is the ciphertext block in front of ``block`` -- the real IV for the
    first block, the previous ciphertext block otherwise. It is the only part of
    the input the attack controls, and controlling it is the whole mechanism.
    """

    if not isinstance(iv, (bytes, bytearray)) or len(iv) != block_size:
        raise ValueError("the preceding block must be %d bytes" % block_size)
    if not isinstance(block, (bytes, bytearray)) or len(block) != block_size:
        raise ValueError("the target block must be %d bytes" % block_size)
    iv = bytes(iv)
    block = bytes(block)

    recovered = bytearray(block_size)
    for index in range(block_size - 1, -1, -1):
        pad = block_size - index
        crafted = bytearray(iv)
        # Make every byte after this one decrypt to the padding value, using
        # what has already been recovered.
        for position in range(index + 1, block_size):
            crafted[position] = iv[position] ^ recovered[position] ^ pad

        found = None
        for guess in range(256):
            crafted[index] = iv[index] ^ guess ^ pad
            if not oracle(bytes(crafted), block):
                continue
            if index == block_size - 1:
                # A one-byte padding of 0x01 is not the only thing that can look
                # valid here: a genuine 0x02 0x02 also accepts the last byte. So
                # disturb the byte before it, which breaks 0x02 0x02 but leaves
                # 0x01 alone, and keep the guess only if the oracle still says
                # yes.
                disturbed = bytearray(crafted)
                disturbed[index - 1] ^= 0x01
                if not oracle(bytes(disturbed), block):
                    continue
            found = guess
            break

        if found is None:
            raise ValueError(
                "the oracle rejected all 256 candidates at byte %d, so it is not "
                "a padding oracle for this key and block size" % index
            )
        recovered[index] = found
    return bytes(recovered)


def recover_plaintext(oracle, iv: bytes, ciphertext: bytes, block_size: int = CBC_BLOCK_SIZE) -> bytes:
    """Recover the whole message, padding included, one block at a time."""

    if not isinstance(iv, (bytes, bytearray)) or len(iv) != block_size:
        raise ValueError("the IV must be %d bytes" % block_size)
    if not isinstance(ciphertext, (bytes, bytearray)) or len(ciphertext) % block_size:
        raise ValueError("the ciphertext must be a whole number of blocks")
    ciphertext = bytes(ciphertext)

    out = bytearray()
    previous = bytes(iv)
    for offset in range(0, len(ciphertext), block_size):
        block = ciphertext[offset:offset + block_size]
        out += recover_block(oracle, previous, block, block_size)
        previous = block
    return bytes(out)
