# Architecture

The module graph is a short chain rather than a web, and that is deliberate: each primitive depends on at most one other, so a failure has one place to be.

```
src/aes.py        the block cipher, the key schedule, counter mode
src/cbc.py        depends on src/aes.py
src/gf128.py      the field GHASH is defined over, on its own
src/gcm.py        depends on src/aes.py and src/gf128.py
src/sha256.py     the compression function, one-shot, streaming, and resumable
src/hmac.py       depends on src/sha256.py
src/ecdsa.py      depends on src/sha256.py (for the RFC 6979 nonce)

src/attacks/length_extension.py    depends on src/sha256.py
src/attacks/nonce_reuse_gcm.py     depends on src/gcm.py, src/gf128.py, src/aes.py
src/attacks/padding_oracle.py      depends on src/cbc.py
src/attacks/nonce_reuse_ecdsa.py   depends on src/ecdsa.py

src/cli.py        depends on all of the above
```

Nothing imports `src/cli.py`, so the command line can change without touching a primitive. Nothing under `src/` imports anything outside the standard library, so the toolkit runs anywhere Python runs. The only third-party import in the project is in the tests, where `cryptography` serves as the reference implementation for the differential comparisons.

`src/gf128.py` exists because two callers need the same multiplication. GHASH uses it to compute tags, and the nonce-reuse attack uses it to solve for the hash subkey. Had the attack carried its own copy, a disagreement between the two would have shown up as a failed attack rather than as a bug, which is the worst possible way for a bug to present itself.

`INTERFACES.md` sits beside the code as the written contract: the signature of every public function, the error each one raises, and the published values each module has to reproduce. It was frozen before the modules were written and the tests assert against it, so a change to a signature is a change to that file first.

The tests mirror the modules one for one, with one file per attack. Each primitive's test file is divided the same way: the published vectors first, then the differential comparison. The attack tests are different in kind -- they assert against the genuine implementation rather than against constants, because that is the only kind of assertion that would notice if the vulnerable construction were replaced with a safe one.
