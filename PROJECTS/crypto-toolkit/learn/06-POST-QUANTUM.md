# The post-quantum half

The other notes describe arithmetic over a finite field and a curve. This one is
about the part of the project where the mathematics stops being optional: ML-KEM
is a lattice scheme, and there is no way to write it by pattern-matching a
familiar construction. Everything before it in this repository has an analogue
you have met -- a block cipher, a Merkle-Damgard hash, a curve. ML-KEM does not.

## Why SHA-3 came first

ML-KEM does not use SHA-256. FIPS 203 specifies SHA3-256 for its hash H,
SHA3-512 for its expander G, SHAKE256 for the pseudorandom function and the
implicit-rejection hash, and SHAKE128 for expanding the public matrix. So the
Keccak permutation had to exist before any of it could be tested, and it is
written as its own module with its own vectors rather than buried inside
`src/mlkem.py`. A bug in the permutation would otherwise surface as a lattice
that does not reproduce its vectors, which is a much harder thing to read.

Six functions share one sponge. SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128
and SHAKE256 differ only in the rate and in two bits of domain separation, so
they are parameterised rather than written out six times. Writing them out
separately is how they drift apart.

## The ring, and why the transform is not an optimisation

The scheme works in `R_q = Z_q[X]/(X^256 + 1)`, where q is 3329 and the
polynomials have 256 coefficients. Multiplying two such polynomials directly is
65,536 coefficient multiplications. The number-theoretic transform maps the ring
into a product of 128 quadratic extensions, where multiplication is one
two-by-two case per extension -- 128 of them.

It would be reasonable to read that as a performance trick. FIPS 203 says
explicitly that it is not, and the standard is right: the transform is what makes
the scheme's arithmetic *expressible*, and the compression, the sampling and the
failure analysis all assume the transformed representation. It is part of the
definition rather than a way to speed up the definition.

## What makes it hard to get right

Three things in particular, all of which this project got wrong at least once:

**Two tables of twiddles that look like one.** The transform uses
`zeta^BitRev7(i)`; multiplication in the transformed domain uses
`zeta^(2*BitRev7(i)+1)`. Using the wrong one raises nothing, because every entry
is still a field element.

**A decoder that is deliberately not an inverse.** `ByteDecode12` reduces modulo
q after reading a 12-bit segment, so it does not undo `ByteEncode12` for a
segment above q. That is the public-key modulus check, and it is invisible until
you test a key that should be refused.

**Sampling that rejects.** The public matrix is sampled by reading three bytes at
a time from a SHAKE128 stream and discarding values at or above q. The output
therefore depends on the *stream*, not on the number of bytes consumed, which is
why the code squeezes one block and walks it rather than squeezing three bytes in
a loop. FIPS 203 states that the two are equivalent; the test suite asserts the
property that makes it true, that a longer SHAKE output is a prefix extension of
a shorter one.

## Why the vectors carry more weight here

Everywhere else in this repository there is a second opinion. AES, CBC, GCM,
ECDSA and RSA-OAEP are all compared against `cryptography`, and SHA-3 against
`hashlib`. There is no ML-KEM in either. NIST's ACVP vectors are not one of two
checks here -- they are the only external check, which is why all three functions
and all three parameter sets are exercised rather than sampled, and why the
structural properties are tested directly as well: that the transform is an
isomorphism, that multiplication in the transformed domain agrees with
negacyclic schoolbook multiplication, and that compression round-trips.

## The comparison, and the honest reading of it

The benchmark exists because the plan asked for one, and the result is not the
story people expect. ML-KEM is not smaller than RSA -- at a comparable strength
its keys and ciphertexts are several times larger. What it buys is resistance to
Shor's algorithm and a much cheaper key generation. And its encapsulation is
*slower* than RSA's encryption, because RSA's public operation uses a small
exponent; it is against RSA's decryption that ML-KEM wins. A benchmark that
reported only the favourable comparison would be a worse result than no
benchmark, because it would look like evidence.

[Back to the project guide](../README.md)
