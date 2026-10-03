# Concepts

A digest is represented as hexadecimal text, with two characters for each byte. Candidate encoding matters: this project uses UTF-8 for the fast hashes and UTF-16LE for NTLM. A wordlist attack tests known candidates in order, so the attempt count is an actual measurement of work performed, and dividing it by the elapsed time gives the hashes-per-second rate reported at the end of a run.

Digest length is a useful but incomplete clue to the algorithm. MD5 and NTLM are both 16 bytes, so a 32-character digest is ambiguous between them and the tool insists on being told which one, or on `--all`. NTLM is not a hash of the password text directly; it is the unsalted MD4 of the password encoded as UTF-16LE, which is why a salt cannot be applied to it.

A salt is extra data combined with the candidate before hashing, so the same password produces different digests in different records. The conventional `hash:salt` layout appends the salt to the password and `salt:hash` prepends it. Mangling rules turn one word into several plausible variants — a capital, an all-caps form, a numeric or punctuation suffix, and basic leetspeak — and a bounded brute-force range tries the shortest lowercase-alphanumeric strings, which is a way to reach very short passwords that no wordlist contains.

MD5 and SHA-1 remain available for examining legacy evidence, but they are not suitable choices for new password storage. Slow, salted password KDFs such as Argon2id, scrypt, or bcrypt make guessing more expensive and are selected by the application storing the password.

[Back to the project guide](../README.md)
