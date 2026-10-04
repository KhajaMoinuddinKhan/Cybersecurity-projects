# Implementation

**The S-box is computed, not pasted.** `src/aes.py` derives it: multiplicative inverse in GF(2**8), then the affine transform. A literal table would be shorter and would also be an opaque block of 256 numbers that nobody can check. Computing it means the file contains the rule the standard states, and a test can confirm the first entry is `0x63` and the structure is a permutation.

**Counter mode is a stream object.** `CTR` holds the counter block and advances it as data arrives, so a caller can feed a file in chunks and never hold the whole thing. `ctr_keystream` is the function underneath it, kept public because a keystream is easier to compare against a published vector than a ciphertext is.

**GCM computes the tag before it decrypts.** The verification step comes first and raises before any plaintext is produced, so a caller cannot end up holding unauthenticated bytes because they forgot to check a return value. The tag comparison XORs the bytes and accumulates, rather than returning at the first difference.

**GHASH names its units.** The final block is written as `(len(aad) * 8) << 64 | (len(ciphertext) * 8)`, with the multiplication by eight visible, because that is the step that is silently wrong in most hand-written versions and it is worth being able to see.

**The initial counter has two branches.** A twelve-byte nonce gets the fast path the specification recommends -- the counter starts at one in the last four bytes. Any other length is hashed into a block first, and that branch is implemented and tested even though it is not the recommended one, because it is the branch that is usually wrong and a reader comparing this to the specification will look for it.

**The command line reports rather than raises.** A bad hex argument, an unreadable file or a tag that does not verify each produce a sentence on standard error and a non-zero exit, not a traceback. The verbs are thin on purpose; they exist so the vectors can be re-checked from a shell.
