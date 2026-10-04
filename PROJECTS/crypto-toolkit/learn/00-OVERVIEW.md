# Overview

This project answers two questions with the same material. The first is whether an implementation agrees with the standard it claims to implement, and how anyone would know -- a cryptographic primitive produces a value that looks random whether or not it is right, so "it ran and produced output" is worth nothing. The second is what happens when the same construction is used slightly wrongly, and the answer is that the wrongness is usually not subtle at all: a MAC that can be extended without the key, a key stream used twice, a padding error that answers a question, a signature nonce that repeats.

Both halves are the point. The primitives are written out so the arithmetic is visible, and then attacked so the reason for each rule in the standards becomes something you have watched happen rather than something you have read.

What is here now: AES at all three key sizes with counter mode and CBC, GCM as authenticated encryption, SHA-256, HMAC-SHA256, and ECDSA over P-256 including the RFC 6979 deterministic nonce. Alongside them, four attacks -- length extension against a naive MAC, nonce reuse against GCM, a padding oracle against CBC, and nonce reuse against ECDSA -- each mounted against the code in this repository and each verified by recovering or forging something and checking it against the genuine implementation.

What is not here: RSA, key exchange, any curve other than P-256, and the post-quantum benchmark. The README says so in the same place it says what the code does.

The rest of these notes take the arithmetic first, because that is where the difficulty lives; then the module graph; then the decisions that shaped the code; then the four attacks; and finally the mistakes, which are the part worth reading if you are writing a cipher yourself.
