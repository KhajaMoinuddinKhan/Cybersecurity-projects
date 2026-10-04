# Interface contract - crypto-toolkit

Frozen before the modules were written, so that each file can be built and
tested on its own. Nothing here may drift: if a module needs a different
signature, the signature changes here first and every caller is updated in the
same change.

**Nothing under `src/` may import a third-party package.** The primitives are
the deliverable. The only exception in the whole project is `cryptography`,
which the *tests* use as a reference implementation to compare against; it must
never appear in `src/`.

## src/aes.py

```python
AES_BLOCK_SIZE = 16

class AES:
    def __init__(self, key: bytes) -> None: ...
    def encrypt_block(self, block: bytes) -> bytes: ...   # 16 bytes in, 16 out
    def decrypt_block(self, block: bytes) -> bytes: ...
    def encrypt(self, data: bytes) -> bytes: ...          # ECB, len(data) % 16 == 0
    def decrypt(self, data: bytes) -> bytes: ...

def ctr_keystream(key: bytes, initial_counter_block: bytes, length: int) -> bytes: ...

class CTR:
    """The counter mode as a stream, so it can be applied to any length."""
    def __init__(self, key: bytes, initial_counter_block: bytes) -> None: ...
    def update(self, data: bytes) -> bytes: ...           # symmetric: decrypt is encrypt

def xor_bytes(left: bytes, right: bytes) -> bytes: ...
```

`AES(key)` accepts 16, 24 or 32 bytes and raises `ValueError` for anything else.
`encrypt_block` / `decrypt_block` raise `ValueError` for a block that is not
exactly 16 bytes. `encrypt` / `decrypt` raise `ValueError` when the data length
is not a multiple of the block size.

`xor_bytes` requires both arguments to be the same length and raises
`ValueError` when they are not. It does not truncate to the shorter one: inside a
counter-mode loop a silent truncation would hand back a keystream of the wrong
length and a ciphertext that is merely wrong, which is harder to notice than an
error. A caller with a partial final block slices the keystream itself, as
`src/gcm.py` does.

## src/gcm.py

```python
class InvalidTag(ValueError): ...

class GCM:
    def __init__(self, key: bytes) -> None: ...
    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]: ...
    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes: ...

def ghash(h: bytes, aad: bytes, ciphertext: bytes) -> bytes: ...
```

`encrypt` returns `(ciphertext, tag)` with a 16-byte tag. `decrypt` raises
`InvalidTag` when the tag does not match and returns nothing in that case.
`GCM` may use `src/aes.py` and nothing else.

## src/sha256.py

```python
SHA256_DIGEST_SIZE = 32

def sha256(data: bytes) -> bytes: ...                     # 32-byte digest
def sha256_hex(data: bytes) -> str: ...                   # 64 lowercase hex characters

class SHA256:
    """Streaming form, so a large input does not have to be held in memory."""
    def __init__(self) -> None: ...
    def update(self, data: bytes) -> "SHA256": ...        # returns self
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def copy(self) -> "SHA256": ...
```

## src/hmac.py

```python
def hmac_sha256(key: bytes, message: bytes) -> bytes: ...
def hmac_sha256_hex(key: bytes, message: bytes) -> str: ...
def constant_time_compare(left: bytes, right: bytes) -> bool: ...
```

`hmac_sha256` must use `src/sha256.py`. A key longer than the 64-byte block is
hashed first, as RFC 2104 requires.

## Published vectors the tests must assert

These are the external check. A test that only compares the implementation to
itself proves nothing, so each module asserts the published values below
verbatim, and additionally cross-checks random inputs against the reference
implementation in `cryptography` (skipped when it is not installed).

**FIPS-197, AES-128 and AES-256**

| key | plaintext | ciphertext |
| --- | --- | --- |
| `000102030405060708090a0b0c0d0e0f` | `00112233445566778899aabbccddeeff` | `69c4e0d86a7b0430d8cdb78070b4c55a` |
| `2b7e151628aed2a6abf7158809cf4f3c` | `3243f6a8885a308d313198a2e0370734` | `3925841d02dc09fbdc118597196a0b32` |
| `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` | `00112233445566778899aabbccddeeff` | `8ea2b7ca516745bfeafc49904b496089` |

**NIST SP 800-38A, AES-128-CTR (F.5.1)** - key `2b7e151628aed2a6abf7158809cf4f3c`,
initial counter block `f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff`

plaintext `6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710`
ciphertext `874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee`

**NIST SP 800-38D, GCM**

| # | key | nonce | plaintext | aad | ciphertext | tag |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 16 zero bytes | 12 zero bytes | empty | empty | empty | `58e2fccefa7e3061367f1d57a4e7455a` |
| 2 | 16 zero bytes | 12 zero bytes | 16 zero bytes | empty | `0388dace60b6a392f328c2b971b2fe78` | `ab6e47d42cec13bdf53a67b21257bddf` |
| 3 | `feffe9928665731c6d6a8f9467308308` | `cafebabefacedbaddecaf888` | `d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39` | empty | `42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091` | `4d5c2af327cd64a62cf35abd2ba6fab4` |

**FIPS-180-4, SHA-256**

| input | digest |
| --- | --- |
| empty | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `abc` | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| `abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq` | `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1` |

**RFC 4231, HMAC-SHA256**

| # | key | data | digest |
| --- | --- | --- | --- |
| 1 | `0b` x 20 | `Hi There` | `b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7` |
| 2 | `Jefe` | `what do ya want for nothing?` | `5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843` |
| 3 | `aa` x 20 | `dd` x 50 | `773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe` |
| 4 | `0102030405060708090a0b0c0d0e0f10111213141516171819` | `cd` x 50 | `82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b` |
| 6 | `aa` x 131 | `Test Using Larger Than Block-Size Key - Hash Key First` | `60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54` |

## Errors

Every module raises `ValueError` for a malformed input - a wrong key length, a
block that is not 16 bytes, a nonce that is not a sensible length - and never
`IndexError`, `struct.error` or an assertion. `src/gcm.py` raises its own
`InvalidTag`, which subclasses `ValueError`, for a tag that does not verify.
