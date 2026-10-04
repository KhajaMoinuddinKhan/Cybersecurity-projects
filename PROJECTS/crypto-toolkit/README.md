# Cryptographic toolkit

A cryptographic library written from the primitives up, and the attacks that
break the naive versions of the same constructions. Nothing in `src/` imports a
cryptography package: AES is written out as a key schedule and a round
function, SHA-256 as a message schedule and a compression function, and GCM as
counter mode bolted to a polynomial hash over GF(2**128). The point is not to
replace a real library. The point is that the arithmetic is visible, and that
the behaviour can be checked against the standard's own worked examples rather
than taken on trust.

The project is being built in four stages and this repository is at the first
one. What is here now is the symmetric half: AES-128, AES-192 and AES-256 as a
block cipher, counter mode, GCM as authenticated encryption, SHA-256 and
HMAC-SHA256. The public-key half, the attacks and the post-quantum benchmark
come next, and the section on what is not here yet says exactly what is missing.

## Why write a cipher out by hand

AES has a shape that is easy to describe and hard to get exactly right. The
S-box is defined as the multiplicative inverse in GF(2**8) followed by an affine
transform; the round function moves bytes between columns and mixes each column
with a fixed polynomial; the key schedule expands a 128-bit key into eleven
128-bit round keys, and a 256-bit key into fifteen. Every one of those steps has
an inverse, and a decryption that is *nearly* the inverse of encryption
produces plausible-looking output that fails on some inputs and not others.
That is the kind of bug that a hand-written cipher has and a borrowed one does
not, and the only way to be sure is to compare against values someone else
published.

GCM is the same story with a sharper edge. It is counter mode, which is
straightforward, plus GHASH, which is not. GHASH multiplies 128-bit blocks in a
field where the bit ordering is unusual: the specification numbers the bits so
that the leftmost bit of a block is the coefficient of x**0, and the reduction
polynomial is applied when the *low* bit of the running value falls off the
end. Get the ordering backwards and every tag is wrong in a way that looks
random rather than wrong. Get the padding or the length block wrong and short
messages pass while long ones fail, because the published examples for the
shortest cases never exercise the chaining.

## What is implemented

| Primitive | File | What it covers |
| --- | --- | --- |
| AES block cipher | `src/aes.py` | 128, 192 and 256-bit keys, encryption and decryption, the key schedule and the round function written out |
| Counter mode | `src/aes.py` | the AES-CTR keystream and a streaming `CTR` object, symmetric so decryption is the same call |
| GCM | `src/gcm.py` | authenticated encryption with a 16-byte tag, GHASH over GF(2**128), associated data, nonces of any length |
| SHA-256 | `src/sha256.py` | the compression function, a one-shot digest and a streaming class |
| HMAC-SHA256 | `src/hmac.py` | RFC 2104 over the local SHA-256, including the key-padding rule at both ends of the block size |

## How it is checked

Two kinds of test, answering two different questions.

The first asserts the **published worked examples** verbatim. FIPS-197 supplies
the AES-128, AES-192 and AES-256 known-answer vectors; NIST SP 800-38A supplies
the counter-mode vector; NIST SP 800-38D supplies four GCM cases including the
empty-plaintext case whose tag proves the hash subkey and the initial counter
are right; FIPS-180-4 supplies the SHA-256 vectors; RFC 4231 supplies the
HMAC-SHA256 vectors, including one whose key is longer than the block size. A
test that only compares this implementation to itself proves nothing, so these
values came from outside.

The second compares **against an independent implementation over random
inputs**. For SHA-256 and HMAC the reference is the standard library, which is
a second implementation written by other people; for AES and GCM it is the
`cryptography` package. Thousands of cases are generated from a fixed seed —
every key size, every nonce length the reference accepts, plaintext and
associated data from empty to a few hundred bytes, and the lengths that land
exactly on a block boundary — and any disagreement fails the suite.

The second kind is the one that earns its keep. A hand-written GHASH can
reproduce the first two published GCM cases, both of which hash a single block,
and still be wrong for every longer message; only the differential test notices.
`cryptography` therefore appears in `requirements.txt` and nowhere else: it is
an oracle for the tests, and `src/` must never import it. The suite fails rather
than skips if it is missing, because a differential test that quietly does
nothing is worse than no test at all.

## Running it

```console
python -m src.cli vectors
python -m src.cli hash path/to/file
python -m src.cli hmac 4a656665 "what do ya want for nothing?"
python -m src.cli seal feffe9928665731c6d6a8f9467308308 cafebabefacedbaddecaf888 path/to/file
python -m src.cli open feffe9928665731c6d6a8f9467308308 cafebabefacedbaddecaf888 <ciphertext> <tag>
```

`vectors` re-checks the published GCM examples and prints one line per case, so
the arithmetic can be confirmed on any machine without a test runner. `hash`
reads a file or standard input. `seal` prints the ciphertext and the tag in hex;
`open` verifies the tag before it does anything else, prints the plaintext in
hex, and takes `--out` when you want the raw bytes written to a file. A tag that
does not match exits non-zero and prints nothing.

## Limits

These are part of the description rather than a disclaimer, because they bound
what the code is for.

- **This is a teaching implementation, not a hardened one.** It is written for a
  reader to follow, and it has not been audited. Use a real library for anything
  that matters.
- **Constant-time behaviour is claimed only where it is written.** HMAC's tag
  comparison and GCM's tag comparison compare without stopping at the first
  difference, and the GCM decryption path verifies before it decrypts. Nothing
  else here makes that claim: the AES S-box is a table lookup, and a table
  lookup on a shared cache is a timing signal. That is a real property of this
  code, and it is why it is not a library.
- **The public-key half is not here yet.** There is no RSA, no ECDSA and no
  key exchange, so there is nothing here that uses a private key.
- **No attacks yet.** The padding oracle, the length-extension attack, the GCM
  nonce-reuse recovery and the ECDSA nonce-reuse recovery are the next stage of
  the project and none of them is implemented.
- **No post-quantum implementation yet.** ML-KEM at a toy parameter set, and the
  benchmark against RSA, come after that.
- **The command line takes keys as arguments.** That is fine for reproducing a
  test vector and wrong for anything else, because a command line is visible to
  every other process on the machine. It is a demonstration surface.
- **GCM here accepts nonces of any length, which is not a recommendation.** The
  specification's fast path is a 96-bit nonce and that is what a caller should
  use. Longer and shorter nonces take the hashing branch, which is implemented
  and tested because it is the branch that is usually wrong, not because it is a
  good idea.
- **No streaming for GCM.** The whole message is held in memory. SHA-256 has a
  streaming class; GCM does not, and a message longer than 2**32 blocks is
  refused by the specification rather than handled here.

## Interface

`INTERFACES.md` is the contract the modules were built against: every signature,
and the published values each module has to reproduce. It is the file to read
before changing anything, because the modules import each other through it.

## API

The library is a package rather than a service, so the surface is Python:

```python
from src.aes import AES
from src.gcm import GCM, InvalidTag
from src.hmac import hmac_sha256_hex
from src.sha256 import sha256_hex

sha256_hex(b"abc")                       # the FIPS-180-4 digest, as hex
hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?")
ciphertext, tag = GCM(key).encrypt(nonce, plaintext, aad)
plaintext = GCM(key).decrypt(nonce, ciphertext, tag, aad)   # raises InvalidTag
AES(key).encrypt_block(block)
```

## Tests

```console
python -m pytest -q tests
```

The suite is organised by module, and each module's tests are in two halves: the
published vectors, and the differential comparison against the reference. The
command-line tests drive the real verbs and assert what a shell would see,
including the refusal path for a tampered tag.
