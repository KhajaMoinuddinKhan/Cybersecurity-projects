# Overview

A cryptographic hash is designed to be easy to calculate and difficult to reverse directly. Offline recovery works by hashing candidates and comparing digests. The quality of the result depends on the candidate source and the hash scheme; the program cannot recover a value that is absent from the supplied wordlist.

This tool is intentionally a local comparison engine. The authorization boundary is part of the design because testing a remote login would create a different, riskier problem.
