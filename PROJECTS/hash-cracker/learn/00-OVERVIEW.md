# Overview

A cryptographic hash is designed to be easy to calculate and difficult to reverse directly. Offline recovery works by hashing candidates and comparing digests. The quality of the result depends on the candidate source and the hash scheme; the program cannot recover a value that is absent from the candidates it was given.

This project now behaves like a small wordlist cracker rather than a single comparison. It detects the algorithm from the digest, understands the common fast hashes and the Windows NTLM format, combines a salt the way the target layout says it should, and can expand each word with a fixed set of mangling rules. It also accepts several digests at once and can add a deliberately tiny brute-force range, all while reporting the measured work.

The authorization boundary is part of the design because testing a remote login would create a different, riskier problem.

[Back to the project guide](../README.md)
