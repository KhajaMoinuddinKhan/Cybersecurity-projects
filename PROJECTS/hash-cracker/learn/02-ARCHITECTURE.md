# Architecture

The CLI validates file and digest arguments, the wordlist reader provides a lazy iterator, and the cracking function owns comparison and timing. A `CrackResult` makes success, failure, algorithm, attempt count, and duration explicit for both the CLI and tests.

There is no network client in this architecture. This prevents the project from turning an educational hash comparison into a remote authentication attack.
