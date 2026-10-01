# Concepts

A digest is represented as hexadecimal text, with two characters for each byte. Candidate encoding matters: this project uses UTF-8 consistently. A wordlist attack tests known candidates in order, so the attempt count is an actual measurement of work performed.

MD5 and SHA-1 remain available for examining legacy evidence, but they are not suitable choices for new password storage. Slow, salted password KDFs such as Argon2id, scrypt, or bcrypt make guessing more expensive and are selected by the application storing the password.
