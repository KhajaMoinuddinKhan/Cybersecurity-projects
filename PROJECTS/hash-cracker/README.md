# Hash Cracker

An offline hash-recovery exercise. You supply one or more digests and the candidates you are entitled to try — a wordlist, a small brute-force range, or both — and the tool hashes each candidate, tells you whether one of them matches, and reports how many candidates it tested, how long it took, and how many hashes per second that worked out to.

That last part is the point. Watching a few hundred thousand candidates turn into a real elapsed time is a much better lesson about password strength than being told that short passwords are weak.

## Running it

Standard library only. Create a digest you are entitled to test, then try a wordlist against it:

```console
python -m src.cracker <hex-digest> --wordlist words.txt --algorithm sha256
```

`--algorithm` accepts `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512` and `ntlm`, and is detected from the digest when you leave it out. The older digests are here because you meet them in real evidence, not because they are a good choice for storing anything. NTLM is the unsalted MD4 of the UTF-16LE password, the format Windows stores in its SAM database.

Detection uses the digest's length and hexadecimal form. MD5 and NTLM are both 32 hexadecimal characters, so a digest of that length is ambiguous and the tool will not guess: name the algorithm, or pass `--all` to try every algorithm whose length matches.

### Several hashes at once

Pass more than one digest and each is reported separately. Algorithms are detected per digest:

```console
python -m src.cracker 4104d36f8da2c254349f85836793ebe029e0c957063a34c91c2e9203187b5631 6e2f9e6111e77edd0c446ea7a84e25323d137a61 --wordlist words.txt
```

### Salted hashes

A salt is combined with each candidate before hashing. Pass it explicitly with `--salt`, or embed it in the target using the conventional layouts:

```console
python -m src.cracker d89eddeec748c49d5add2f8f347b8899:pepper --wordlist words.txt --algorithm md5   # hash:salt
python -m src.cracker pepper:fb985bc394cf7ec1f46feac5ff63ca9f --wordlist words.txt --algorithm md5   # salt:hash
python -m src.cracker d89eddeec748c49d5add2f8f347b8899 --wordlist words.txt --algorithm md5 --salt pepper --salt-position suffix
```

`hash:salt` appends the salt to the candidate; `salt:hash` prepends it. `--salt-position` says which applies when you pass `--salt` yourself, and can override the layout when both fields happen to look like digests. NTLM is unsalted, so combining it with a salt is refused.

### Rules

`--rules` mangles every candidate word before testing it. The rule set is fixed and documented in full under [The rules](#the-rules). It multiplies the candidates; it does not make the search space any smarter.

### Short brute force

`--brute N` additionally tries every lowercase-alphanumeric string from length 1 up to N. The alphabet is 26 letters plus 10 digits, so the search space grows fast; the tool refuses a range above 2,000,000 candidates and tells you the number it would have tested:

```console
$ python -m src.cracker 5f4dcc3b5aa765d61d8327deb882cf99 --brute 5 --algorithm md5
Hash recovery failed: --brute 5 would test 62,193,780 candidates, above the 2,000,000 limit; choose a smaller length
```

Length 4 (1,727,604 candidates) is allowed; length 5 is not.

### JSON report

`--json` prints the same measured work as a machine-readable report instead of text.

## What the output looks like

```
Target: 4104d36f8da2c254349f85836793ebe029e0c957063a34c91c2e9203187b5631
Algorithm: sha256
Candidates tested: 4
Elapsed seconds: 0.007547
Hashes per second: 530.03
Match found: correct horse
```

When nothing matches, the tool says so and exits with status 1, which makes it usable in a shell pipeline. With several targets, a target that is ambiguous or malformed is reported with its own error and the rest are still tried.

## The rules

`--rules` tests each word itself plus the following variants. The suffixes are the tuples in `src/cracker.py`, so this list is exactly what runs.

| Rule | Variant |
| --- | --- |
| `capitalise` | first character upper-cased, the rest unchanged |
| `uppercase` | the whole word upper-cased |
| `append-numeric` | the word followed by `1`, `12`, `123` and `1234` |
| `append-punctuation` | the word followed by `!`, `.`, `?`, `@` and `#` |
| `leetspeak` | one variant per substituted letter (`a`→`4`, `e`→`3`, `i`→`1`, `o`→`0`, `s`→`5`, `t`→`7`), plus one with every eligible letter substituted |

The base word is always tried and duplicate variants are dropped. So `--rules` turns `password` into: `password`, `Password`, `PASSWORD`, `password1`, `password12`, `password123`, `password1234`, `password!`, `password.`, `password?`, `password@`, `password#`, `p4ssword`, `pa5sword`, `pas5word`, `passw0rd`, `p455w0rd`.

## How it works

`wordlist_candidates()` reads the wordlist one line at a time, so memory use tracks the current candidate rather than the size of the file. Blank lines are skipped and a byte order mark at the start of the file is tolerated. `detect_algorithms()` decides the algorithm from the digest's length and hexadecimal form, and `parse_target()` splits a `hash:salt` or `salt:hash` target. `validate_target()` checks the digest length and form before any work starts, and an unsupported algorithm name is rejected up front with the list of valid ones. Each algorithm is tested by replaying the candidate stream, so a wordlist is never held in memory.

There is no GPU path, no remote mode, and no built-in password list. The only candidates that get tried are the ones you supply or the bounded brute-force range you ask for.

## Limits

This is a wordlist and rules tool. It recovers a password only when a candidate you supply, a variant a rule produces, or a string inside the brute-force range hashes to the target. A password outside that candidate space is not recovered, however weak it is in the abstract.

- It is not competitive with GPU cracking tools such as hashcat or John the Ripper. The hashing is single-threaded Python; the hashes-per-second figure is honest for this program, not a statement about how fast an attacker would be.
- MD4 is not exposed by every OpenSSL build, so NTLM falls back to a pure-Python MD4 implementation when `hashlib` cannot provide it. The fallback is correct but slow, which makes NTLM runs the slowest here.
- The brute-force mode is deliberately tiny. Length 4 is the largest range this build allows, and even that is over a million hashes.
- The rules are the five above, applied once to each word. There is no combinatorial rule chaining, no mask attack and no hashcat `.rule` file support.
- A match is evidence about one digest, not proof about a person or a reused password.
- Digests produced by a slow password KDF (bcrypt, scrypt, Argon2id) are out of scope; the supported algorithms are fast hashes.

## Scope

Only test hashes you have permission to test, and treat a recovered value as evidence rather than a credential: do not use it to sign in anywhere. If your wordlist contains real passwords, delete it when the exercise is over.

## Tests

```console
python -m pytest -q tests
```

Tests use digests generated inside the test process, and cover matches, no-match results, streamed wordlists with blank lines, invalid digests, unsupported algorithm names, algorithm auto-detection and its ambiguous and unrecognised cases, the `--all` path, NTLM against its known vector, both salt layouts and the explicit salt options, each mangling rule, the brute-force guard and its search-space count, several targets in one run, and the hashes-per-second calculation.
