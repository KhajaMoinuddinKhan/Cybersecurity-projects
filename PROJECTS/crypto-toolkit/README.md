# Cryptographic toolkit and attack lab

A cryptographic library written from the primitives up, and the attacks that
break the naive versions of the same constructions. Nothing in `src/` imports a
cryptography package: AES is written out as a key schedule and a round
function, SHA-256 as a message schedule and a compression function, GCM as
counter mode bolted to a polynomial hash over GF(2**128), CBC as the same block
cipher chained, and ECDSA on an elliptic curve over a 256-bit prime field with
the point arithmetic spelled out. The point is not to replace a real library.
The point is that the arithmetic is visible, and that it can be checked against
the standards' own worked examples rather than taken on trust.

The second half is the reason to write the first half this way. Every attack in
`src/attacks/` is mounted against the code in this repository rather than
against a description of it, and every one of them is verified by recovering or
forging something and then checking it against the genuine implementation -- the
forged MAC is fed back into the MAC function, the forged GCM tag is accepted by
`GCM.decrypt`, the recovered ECDSA key is compared to the key that signed, and
the recovered plaintext to the plaintext that was encrypted. Nothing is
compared to a stored answer, and every key, nonce and message is generated when
the test runs.

## What is implemented

| Primitive | File | What it covers |
| --- | --- | --- |
| AES block cipher | `src/aes.py` | 128, 192 and 256-bit keys, encryption and decryption, the key schedule and the round function written out |
| Counter mode | `src/aes.py` | the AES-CTR keystream and a streaming `CTR` object, symmetric so decryption is the same call |
| CBC | `src/cbc.py` | the chained mode with PKCS#7 padding, and the raw block functions a padding oracle needs |
| GCM | `src/gcm.py` | authenticated encryption with a 16-byte tag, GHASH, associated data, nonces of any length |
| GF(2**128) | `src/gf128.py` | the field arithmetic GHASH uses, on its own, because the nonce-reuse attack needs it too |
| SHA-256 | `src/sha256.py` | the compression function, a one-shot digest, a streaming class, and resumption from a known state |
| HMAC-SHA256 | `src/hmac.py` | RFC 2104 over the local SHA-256, including the key-padding rule at both ends of the block size |
| ECDSA over P-256 | `src/ecdsa.py` | field arithmetic, point operations, scalar multiplication, sign, verify, and the RFC 6979 deterministic nonce |

## What is attacked

| Attack | File | What the attacker gets |
| --- | --- | --- |
| Length extension | `src/attacks/length_extension.py` | A valid MAC for `secret ‖ message ‖ padding ‖ appendage` from one message and its tag, knowing only the secret's *length* |
| GCM nonce reuse | `src/attacks/nonce_reuse_gcm.py` | The hash subkey, the keystream, the other plaintext, and the ability to forge a tag the real implementation accepts |
| Padding oracle | `src/attacks/padding_oracle.py` | The whole plaintext, from nothing but a yes-or-no answer to "is this padding valid" |
| ECDSA nonce reuse | `src/attacks/nonce_reuse_ecdsa.py` | The private key, outright, from two signatures that share a nonce |

Each is a real weakness in a real construction rather than a contrived puzzle,
and each is demonstrated against the code above. `python -m src.cli attack all`
runs all four against freshly generated keys and reports what came out.

## The output

`python -m src.cli attack all` runs each attack against keys, nonces and messages
generated at that moment, and reports what it recovered or forged. Nothing is
compared to a stored answer: the forged MAC goes back into the MAC function with
the real secret, the forged GCM tag into `GCM.decrypt`, and the recovered ECDSA
key into a fresh signature the real verifier has to accept.

![The four attacks](docs/screenshots/01-the-four-attacks.png)

The same primitives are reachable from the shell, and the published vectors
reproduce there without a test runner. A tampered tag is refused before anything
is written to standard output, which is the behaviour the `GCM.decrypt` path is
built around.

![The command line](docs/screenshots/02-the-command-line.png)

![The published vectors and the suite](docs/screenshots/03-vectors-and-tests.png)

## Why write a cipher out by hand

AES has a shape that is easy to describe and hard to get exactly right. The
S-box is defined as the multiplicative inverse in GF(2**8) followed by an affine
transform; the round function moves bytes between columns and mixes each column
with a fixed polynomial; the key schedule expands a 128-bit key into eleven
128-bit round keys, and a 256-bit key into fifteen. Every one of those steps has
an inverse, and a decryption that is *nearly* the inverse of encryption produces
plausible-looking output that fails on some inputs and not others.

GCM is the same story with a sharper edge, and it is where this project spent
most of its debugging. GHASH multiplies 128-bit blocks in a field where the bit
ordering is unusual: the specification numbers the bits so that the leftmost bit
of a block is the coefficient of x**0, and the reduction polynomial is applied
when the *low* bit of the running value falls off the end. Get the ordering
backwards and every tag is wrong in a way that looks random rather than wrong.
There is a second trap underneath that one, which cost a session to find: in
that ordering the field's multiplicative identity is the block with its top bit
set, so the *integer* 1 is x**127 and not 1 at all. An exponentiation seeded
with `result = 1` therefore computes the wrong inverse, and the polynomial
division in the attack below then fails to cancel its leading term and loops
forever rather than returning a wrong answer. Both traps are written down in
`src/gf128.py`, at the place where they bite.

## How it is checked

Two kinds of test, answering two different questions.

The first asserts the **published worked examples** verbatim. FIPS-197 supplies
the AES known-answer vectors; NIST SP 800-38A supplies the counter-mode and the
CBC vectors at all three key sizes; NIST SP 800-38D supplies four GCM cases
including the empty-plaintext case whose tag proves the hash subkey and the
initial counter are right; FIPS-180-4 supplies the SHA-256 vectors; RFC 4231
supplies the HMAC vectors, including one whose key is longer than the block
size; and RFC 6979 supplies the P-256 ECDSA vectors for both the explicit and
the deterministic nonce, which is what ties the whole curve implementation to
the standard. Those values were read out of the specifications rather than from
memory -- the CBC ones out of the NIST PDF, the ECDSA ones out of the RFC text.

The second compares **against an independent implementation over random
inputs**. For SHA-256 and HMAC the reference is the standard library; for AES,
CBC, GCM and ECDSA it is the `cryptography` package. Thousands of cases are
generated from a fixed seed -- every key size, every nonce length the reference
accepts, plaintext and associated data from empty to a few hundred bytes, and
the lengths that land exactly on a block boundary -- and any disagreement fails
the suite.

The second kind is the one that earns its keep. A hand-written GHASH can
reproduce the first two published GCM cases, both of which hash a single block,
and still be wrong for every longer message. `cryptography` therefore appears in
`requirements.txt` and nowhere else: it is an oracle for the tests, and `src/`
must never import it. The suite fails rather than skips if it is missing,
because a differential test that quietly does nothing is worse than no test at
all.

The attacks are checked a third way, which is the one that matters most: the
forgery is handed back to the genuine implementation and has to be accepted.
A test that compared a forgery to a stored value would keep passing if the
construction it attacks were quietly replaced with a safe one.

## Running it

```console
python -m src.cli attack all
python -m src.cli vectors
python -m src.cli hash path/to/file
python -m src.cli hmac 4a656665 "what do ya want for nothing?"
python -m src.cli seal feffe9928665731c6d6a8f9467308308 cafebabefacedbaddecaf888 path/to/file
python -m src.cli open feffe9928665731c6d6a8f9467308308 cafebabefacedbaddecaf888 <ciphertext> <tag>
```

`attack` runs any one of the four or all of them, generating its own keys and
messages and reporting whether the recovery or the forgery actually worked.
`vectors` re-checks the published GCM examples so the arithmetic can be
confirmed on any machine without a test runner. `seal` prints a ciphertext and a
tag in hex; `open` verifies the tag before it does anything else and refuses a
tampered one with a non-zero exit and nothing on standard output.

## Limits

These are part of the description rather than a disclaimer, because they bound
what the code is for.

- **This is a teaching implementation, not a hardened one.** It is written for a
  reader to follow, and it has not been audited. Use a real library for anything
  that matters.
- **Constant-time behaviour is claimed only where it is written.** HMAC's and
  GCM's tag comparisons compare without stopping at the first difference, and
  GCM's decryption path verifies before it decrypts. Nothing else here makes
  that claim: the AES S-box is a table lookup, and a table lookup on a shared
  cache is a timing signal. That is a real property of this code, and it is why
  it is not a library.
- **The public-key half is one algorithm, not a family.** There is ECDSA over
  P-256 and nothing else: no RSA, no RSA-OAEP, no key exchange, no other curve,
  and no signature scheme other than ECDSA.
- **No post-quantum implementation yet.** ML-KEM at a toy parameter set, and the
  benchmark against RSA, are still to come.
- **The attacks are demonstrations, not tools.** Each one targets the
  construction named in its own docstring, and the padding oracle needs a caller
  who actually answers differently for bad padding than for a bad MAC -- which
  is the vulnerability, not something this code can supply on someone else's
  behalf.
- **A single pair of messages does not recover a GCM subkey.** The difference of
  two tags is a polynomial whose every root in GF(2**128) is a genuine
  candidate, so one pair narrows the subkey to a handful and three messages
  under the same nonce are what pin it down. The function says so rather than
  guessing, because that is the shape of the weakness.
- **The command line takes keys as arguments.** That is fine for reproducing a
  test vector and wrong for anything else, because a command line is visible to
  every other process on the machine. It is a demonstration surface.
- **GCM here accepts nonces of any length, which is not a recommendation.** The
  specification's fast path is a 96-bit nonce and that is what a caller should
  use.
- **No streaming for GCM or CBC.** The whole message is held in memory. SHA-256
  has a streaming class; the authenticated modes do not.

## Interface

`INTERFACES.md` is the contract the modules were built against: every signature,
and the published values each module has to reproduce. It is the file to read
before changing anything, because the modules import each other through it.

## API

The library is a package rather than a service, so the surface is Python:

```python
from src.aes import AES
from src.cbc import CBC, pkcs7_unpad
from src.ecdsa import generate_private_key, sign, sign_deterministic, verify
from src.gcm import GCM, InvalidTag
from src.hmac import hmac_sha256_hex
from src.sha256 import sha256_hex

sha256_hex(b"abc")                       # the FIPS-180-4 digest, as hex
ciphertext, tag = GCM(key).encrypt(nonce, plaintext, aad)
plaintext = GCM(key).decrypt(nonce, ciphertext, tag, aad)   # raises InvalidTag
key = generate_private_key(os.urandom(32))
signature = sign_deterministic(key, digest)                 # RFC 6979, no reuse
```

## Tests

```console
python -m pytest -q tests
```

The suite is organised by module, and each module's tests are in two halves: the
published vectors, and the differential comparison against the reference. The
attacks have their own file each, and they assert against the genuine
implementation rather than against constants.
