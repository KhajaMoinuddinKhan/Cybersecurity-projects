# Hash Cracker

An offline hash-recovery exercise. You supply a digest and a wordlist, the tool hashes each candidate and tells you whether one of them matches, how many candidates it tested, and how long it took.

That last part is the point. Watching a few hundred thousand candidates turn into a real elapsed time is a much better lesson about password strength than being told that short passwords are weak.

## Running it

Standard library only. Create a digest you are entitled to test, then try a wordlist against it:

```console
python -m src.cracker <hex-digest> --wordlist words.txt --algorithm sha256
```

`--algorithm` accepts `md5`, `sha1`, `sha224`, `sha256`, `sha384` and `sha512`, and defaults to `sha256`. The older digests are here because you meet them in real evidence, not because they are a good choice for storing anything.

## What the output looks like

```
Algorithm: sha256
Candidates tested: 3
Elapsed seconds: 0.006974
Match found: Summer2026!
```

When nothing matches, the tool says so and exits with status 1, which makes it usable in a shell pipeline:

```
Algorithm: sha256
Candidates tested: 7
Elapsed seconds: 0.000185
No supplied candidate matched the target digest.
```

## How it works

`wordlist_candidates()` reads the wordlist one line at a time, so memory use tracks the current candidate rather than the size of the file. Blank lines are skipped and a byte order mark at the start of the file is tolerated. `validate_target()` checks the digest length and hexadecimal form before any work starts, and an unsupported algorithm name is rejected up front with the list of valid ones.

There is no GPU path, no rule engine, no remote mode, and no built-in password list. The only candidates that get tried are the ones in the file you handed over.

## Scope

Only test hashes you have permission to test, and treat a recovered value as evidence rather than a credential: do not use it to sign in anywhere. If your wordlist contains real passwords, delete it when the exercise is over.

## Tests

```console
python -m pytest -q tests
```

Tests use digests generated inside the test process, and cover matches, no-match results, streamed wordlists with blank lines, invalid digests, and unsupported algorithm names.
