# Architecture

The module graph is a short chain rather than a web, and that is deliberate: each primitive depends on at most one other, so a failure has one place to be.

```
src/aes.py        the block cipher, the key schedule, counter mode
src/gcm.py        depends on src/aes.py
src/sha256.py     the compression function, one-shot and streaming
src/hmac.py       depends on src/sha256.py
src/cli.py        depends on gcm, hmac and sha256
```

Nothing imports `src/cli.py`, so the command line can change without touching a primitive. Nothing under `src/` imports anything outside the standard library, so the toolkit runs anywhere Python runs. The only third-party import in the project is in the tests, where `cryptography` serves as the reference implementation for the differential comparisons.

`INTERFACES.md` sits beside the code as the written contract: the signature of every public function, the error each one raises, and the published values each module has to reproduce. It was frozen before the modules were written and the tests assert against it, so a change to a signature is a change to that file first.

The tests mirror the modules one for one, and each test file is divided the same way: the published vectors first, then the differential comparison. The command-line tests are separate because they exercise the verbs rather than the arithmetic, including the path where a tampered ciphertext is refused.
