# Implementation

**The S-box is computed, not pasted.** `src/aes.py` derives it: multiplicative inverse in GF(2**8), then the affine transform. A literal table would be shorter and would also be an opaque block of 256 numbers that nobody can check. Computing it means the file contains the rule the standard states, and a test can confirm the first entry is `0x63` and the structure is a permutation.

**Counter mode is a stream object.** `CTR` holds the counter block and advances it as data arrives, so a caller can feed a file in chunks and never hold the whole thing. `ctr_keystream` is the function underneath it, kept public because a keystream is easier to compare against a published vector than a ciphertext is.

**GCM computes the tag before it decrypts.** The verification step comes first and raises before any plaintext is produced, so a caller cannot end up holding unauthenticated bytes because they forgot to check a return value. The tag comparison XORs the bytes and accumulates, rather than returning at the first difference.

**GHASH names its units.** The final block is written as `(len(aad) * 8) << 64 | (len(ciphertext) * 8)`, with the multiplication by eight visible, because that is the step that is silently wrong in most hand-written versions and it is worth being able to see.

**The initial counter has two branches.** A twelve-byte nonce gets the fast path the specification recommends -- the counter starts at one in the last four bytes. Any other length is hashed into a block first, and that branch is implemented and tested even though it is not the recommended one, because it is the branch that is usually wrong and a reader comparing this to the specification will look for it.

**The command line reports rather than raises.** A bad hex argument, an unreadable file or a tag that does not verify each produce a sentence on standard error and a non-zero exit, not a traceback. The verbs are thin on purpose; they exist so the vectors can be re-checked from a shell.

**CBC exposes its raw blocks on purpose.** `encrypt_blocks` and `decrypt_blocks` do no padding at all, and `decrypt_blocks` hands back the raw decryption rather than a stripped plaintext. That looks like a leaky interface until you write the padding oracle, which needs to inspect the padding itself: the whole attack is a caller deciding whether the last byte of the raw block forms valid padding, and an API that insisted on unpadding before returning would have nothing to attack.

**ECDSA's sign takes the nonce as an argument.** Every real library derives it internally, precisely so that a caller cannot reuse one. Here it is a parameter, because the attack is the reuse and the attack has to be constructible against the real signing function. The correct way to produce a nonce is `sign_deterministic`, which implements RFC 6979, and that function is tested against the published vectors for both messages so the safe path is as well pinned as the unsafe one.

**The digest conversion is shared, not repeated.** Signing, verifying and the nonce-reuse attack all have to read a message digest as the integer `z` the same way -- big-endian, and only the leftmost bits when the digest is longer than the group order. If the attack had its own conversion and the two disagreed, the recovered key would be wrong and it would look like a broken attack rather than a mismatched reading, so the conversion is public and there is one of it.
