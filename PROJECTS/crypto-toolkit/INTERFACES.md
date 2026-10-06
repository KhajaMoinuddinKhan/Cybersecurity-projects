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


## src/gf128.py

The arithmetic of GHASH, on its own, because the nonce-reuse attack needs the
same field operations that the tag computation uses.

```python
GF128_BLOCK_SIZE = 16

def block_to_int(block: bytes) -> int: ...
def int_to_block(value: int) -> bytes: ...
def gf128_multiply(left: int, right: int) -> int: ...
def gf128_inverse(value: int) -> int: ...
def gf128_power(value: int, exponent: int) -> int: ...
def gf128_square_root(value: int) -> int: ...
```

Field elements are 128-bit integers in the specification's bit order: the most
significant bit of the block is the coefficient of x**0, and the reduction
polynomial is applied when the low bit falls off. `gf128_multiply` must agree
with the multiplication inside `ghash` for every input -- `src/gcm.py` uses it
for exactly that, and a disagreement would break the published vectors.

`gf128_square_root` returns the unique element whose square is the argument. It
is `value ** (2**127)`, which is valid because x -> x**2 is a bijection on
GF(2**128). `gf128_inverse(0)` raises `ValueError`.

## src/sha256.py -- one addition

```python
def sha256_resume(state: bytes, byte_length: int, data: bytes) -> bytes: ...
```

Hash `data` as the continuation of a message whose internal state is `state` (the
32 raw digest bytes of a prefix) and whose length so far is `byte_length` bytes.
This is what makes the length-extension attack possible: the digest of a prefix
is the state you continue from, so a MAC built as `sha256(secret || message)`
can be extended without knowing the secret. The function must agree with the
one-shot digest when `state` is the digest of the prefix and `data` is the rest:

    sha256_resume(sha256(prefix), len(prefix) + len(sha256_padding(len(prefix))), suffix)
        == sha256(prefix + sha256_padding(len(prefix)) + suffix)

## src/cbc.py

```python
CBC_BLOCK_SIZE = 16

class PaddingError(ValueError): ...

def pkcs7_pad(data: bytes, block_size: int = CBC_BLOCK_SIZE) -> bytes: ...
def pkcs7_unpad(data: bytes, block_size: int = CBC_BLOCK_SIZE) -> bytes: ...

class CBC:
    def __init__(self, key: bytes) -> None: ...
    def encrypt(self, iv: bytes, plaintext: bytes) -> bytes: ...
    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes: ...
    def encrypt_blocks(self, iv: bytes, data: bytes) -> bytes: ...
    def decrypt_blocks(self, iv: bytes, data: bytes) -> bytes: ...
```

`encrypt` pads with PKCS#7 and `decrypt` removes the padding, raising
`PaddingError` when it is not valid. `encrypt_blocks` and `decrypt_blocks` work
on data that is already a whole number of blocks and do no padding at all --
`decrypt_blocks` returns the raw decryption so a caller can inspect the padding
itself, which is what a padding oracle does.

PKCS#7 appends N bytes of value N, where N is at least 1: a message that is
already a multiple of the block size gets a whole extra block of padding.
`pkcs7_unpad` raises `PaddingError` when the last byte is 0, is larger than the
block size, or when the trailing bytes do not all carry that value.

The published vectors are the raw-block ones from NIST SP 800-38A appendix F.2:
F.2.1 and F.2.2 for AES-128, F.2.3 and F.2.4 for AES-192, F.2.5 and F.2.6 for
AES-256. All three use key sizes 16, 24 and 32 bytes, the IV
`000102030405060708090a0b0c0d0e0f`, and the same four plaintext blocks
`6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710`, and they
are asserted through `encrypt_blocks` and `decrypt_blocks`.

## src/ecdsa.py

```python
P256_P = ...          # the field prime
P256_A = ...          # -3 mod p
P256_B = ...          # the curve constant
P256_N = ...          # the order of the base point
P256_G = (x, y)       # the base point

class PublicKey:
    def __init__(self, point: tuple[int, int]) -> None: ...
    @property
    def x(self) -> int: ...
    @property
    def y(self) -> int: ...
    def to_bytes(self) -> bytes: ...        # 0x04 || x(32) || y(32)

class PrivateKey:
    def __init__(self, secret: int) -> None: ...
    @property
    def secret(self) -> int: ...
    @property
    def public_key(self) -> PublicKey: ...

def generate_private_key(seed: bytes) -> PrivateKey: ...
def sign(private_key: PrivateKey, digest: bytes, nonce: int) -> tuple[int, int]: ...
def sign_deterministic(private_key: PrivateKey, digest: bytes) -> tuple[int, int]: ...
def verify(public_key: PublicKey, digest: bytes, signature: tuple[int, int]) -> bool: ...
```

`sign` takes the nonce as an argument, deliberately: a caller can then pass the
same nonce twice, which is the mistake the attack demonstrates. `sign` must
reject a nonce outside `1 <= nonce < n`, and `sign_deterministic` implements
RFC 6979 so a caller has a correct way to produce a nonce from the key and the
message.

`generate_private_key` derives the secret from `seed` as
`int.from_bytes(sha256(seed)) mod (n - 1) + 1`, so the same seed gives the same
key and a test can be repeated.

The published vectors are RFC 6979 appendix A.2.5, curve NIST P-256, message
digest SHA-256 of the ASCII strings `sample` and `test`:

    private key x = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    public  Ux = 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
            Uy = 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299

    "sample", SHA-256:  k = A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
                        r = EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
                        s = F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
    "test",   SHA-256:  k = D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0
                        r = F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367
                        s = 019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083

Those values were read out of the RFC text rather than from memory. `sign` with
the published `k` must return the published `r` and `s`, which is what ties the
explicit-nonce path to the standard.

## src/attacks/

Four modules, each a real attack against a real weakness, each verified by
recovering or forging something and then checking it against the genuine
implementation rather than against a stored answer.

```python
# length_extension.py
def naive_mac(secret: bytes, message: bytes) -> bytes: ...
def sha256_padding(message_length: int) -> bytes: ...
def forge_mac(known_mac: bytes, secret_length: int, original_message: bytes,
              appendage: bytes) -> tuple[bytes, bytes]: ...

# nonce_reuse_gcm.py
def recover_hash_subkey(messages: list[tuple[bytes, bytes, bytes]]) -> bytes: ...
def recover_plaintext_pair(ciphertext1: bytes, ciphertext2: bytes,
                           known_plaintext: bytes) -> bytes: ...
def recover_keystream_xor(nonce: bytes, tag: bytes, aad: bytes,
                          ciphertext: bytes, hash_subkey: bytes) -> bytes: ...
def forge_tag(hash_subkey: bytes, nonce: bytes, aad: bytes, ciphertext: bytes,
              known_nonce: bytes, known_tag: bytes, known_aad: bytes,
              known_ciphertext: bytes) -> bytes: ...

# padding_oracle.py
def recover_block(oracle, iv: bytes, block: bytes, block_size: int = 16) -> bytes: ...
def recover_plaintext(oracle, iv: bytes, ciphertext: bytes, block_size: int = 16) -> bytes: ...

# nonce_reuse_ecdsa.py
def recover_nonce(digest1: bytes, signature1: tuple[int, int],
                  digest2: bytes, signature2: tuple[int, int], order: int) -> int: ...
def recover_private_key(digest1: bytes, signature1: tuple[int, int],
                        digest2: bytes, signature2: tuple[int, int], order: int) -> int: ...
```

`forge_mac` returns the forged message and the forged MAC. The forged message is
`original_message || glue || appendage` where `glue` is the SHA-256 padding of
`secret || original_message`, and the MAC must verify under `naive_mac` with the
real secret.

`recover_hash_subkey` takes a list of ``(tag, aad, ciphertext)`` triples produced
under one nonce -- at least three -- and returns the GHASH subkey. It must not be
told H. One pair is deliberately not enough: the difference of two tags is a
polynomial in H of degree equal to the message length in blocks, every root in
GF(2**128) is a genuine candidate, and only the intersection of the candidate
sets from several pairs is the subkey.

`recover_plaintext_pair` returns the second plaintext given the first, using
that the keystream is identical under a repeated nonce.

`forge_tag` produces a tag that the genuine `GCM.decrypt` accepts for a chosen
ciphertext, using the recovered subkey and one known tag under the same nonce.

`recover_block` takes a callable that returns True when a ciphertext decrypts to
valid padding, and returns the plaintext block. `recover_plaintext` does the
whole message.

`recover_private_key` returns the ECDSA private key from two signatures that
share a nonce.


## src/web.py

The local web console. Standard library only, for the same reason everything
else is: nothing under `src/` may import a third-party package, and that rule is
asserted by walking the source with `ast` rather than by trusting a comment.

```python
TEMPLATE_PATH = Path(...) / "templates" / "console.html"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8088

def published_vectors() -> dict: ...
def run_length_extension() -> dict: ...
def run_gcm_nonce_reuse() -> dict: ...
def run_padding_oracle() -> dict: ...
def run_ecdsa_nonce_reuse() -> dict: ...

class Handler(BaseHTTPRequestHandler): ...
def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, *, quiet: bool = False) -> None: ...
```

The routes are `GET /` for the page, `GET /api/vectors`, `GET /api/attack/<name>`
for any of the four, and `POST` to `/api/hash`, `/api/hmac`, `/api/gcm/seal` and
`/api/gcm/open`. A bad request is a 400 carrying an `error` string; an unknown
route is a 404. A failed attack is a 200 with `worked: false`, because a failed
attack is a result and not a crash.

`DEFAULT_HOST` is the loopback address and must stay that way. The console takes
a key and a plaintext from whoever opens it and will encrypt with them.

The page at `src/templates/console.html` is **self-contained**: no stylesheet,
font or script is fetched from anywhere, and every request it makes is a relative
path back to the server that served it. The tests assert the absence of `http://`,
`https://`, `<link`, `<script src`, `@import` and `integrity=` in the file, so the
contract cannot be broken by adding a convenience import.
