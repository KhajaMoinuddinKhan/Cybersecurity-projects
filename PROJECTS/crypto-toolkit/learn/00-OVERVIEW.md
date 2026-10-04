# Overview

This project answers one question with the material a cipher already contains: does this implementation agree with the standard it claims to implement, and how would anyone know? A cryptographic primitive produces a value that looks random whether or not it is right, so "it ran and produced output" is worth nothing. What is worth something is reproducing values somebody else published, and then agreeing with an independent implementation on inputs nobody chose.

The project is being built in four stages. This repository is at the first: the symmetric primitives. AES as a block cipher at all three key sizes, counter mode, GCM as authenticated encryption, SHA-256 and HMAC-SHA256. The public-key primitives come next, then the four attacks against deliberately broken versions of the same constructions, then a post-quantum key encapsulation mechanism and the benchmark that compares it to RSA. The README says which of those are absent, because a reader should not have to work it out from the file list.

The rest of these notes take the arithmetic first, because that is where the difficulty lives; then the module graph; then the decisions that shaped the code; and finally the mistakes, which are the part worth reading if you are writing a cipher yourself.
