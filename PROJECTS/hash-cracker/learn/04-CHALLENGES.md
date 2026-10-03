# Challenges

A large wordlist can take time and disk I/O, and the rules multiply that work without making it more intelligent: a password that is not a simple transformation of a word in the list stays out of reach. The bounded brute-force mode reaches only very short lowercase-alphanumeric strings, and the guard that refuses a large range exists because Python hashing is far slower than the GPU tools this project is not trying to match. The reported hashes per second describe this single-threaded program, not an attacker's hardware.

A match can still be a weak or reused password, and a hash without salt allows the same candidate to be compared across records; password KDFs address that design problem. NTLM is unsalted by definition, which is part of why it is weak. The project does not estimate the strength of a password that was not found, does not handle bcrypt, scrypt or Argon2id, and does not prove that a digest belongs to a particular person.

[Back to the project guide](../README.md)
