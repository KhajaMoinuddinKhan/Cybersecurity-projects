# Implementation

`hashlib.new()` keeps the supported algorithm list explicit while avoiding separate code paths for every digest. NTLM is the exception: because OpenSSL 3 may not expose MD4, `md4_digest()` prefers `hashlib` and falls back to a pure-Python MD4 (RFC 1320) that is checked against the published test vectors. `digest_text()` builds the salted material — password plus salt, or salt plus password — and encodes it before hashing.

Mangling lives in five small functions whose suffixes and substitutions are module constants, so the README can describe exactly the set the code runs. `mangle()` returns the base word plus every variant, dropping duplicates. `brute_candidates()` streams `itertools.product` over a fixed lowercase-alphanumeric alphabet, and `check_brute_length()` sums that space and refuses anything above the cap, naming the number it would have tested. Blank wordlist lines are ignored, other text is retained exactly apart from line endings, and malformed UTF-8 fails clearly. A missing match returns `None` and a nonzero CLI status instead of a made-up answer.

The test suite covers a match, a complete miss, streaming input, invalid target validation, detection and its ambiguous and unrecognised cases, the `--all` path, NTLM, both salt layouts, each rule, the brute-force guard, several targets in one run, and the rate calculation.

[Back to the project guide](../README.md)
