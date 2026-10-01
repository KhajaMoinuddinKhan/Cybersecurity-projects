# Offline hash recovery

This project tests a hash against a wordlist that you supply. It is designed for passwords or test values you own, security labs, and incident-response evidence where offline analysis is authorized. It never connects to a login form, guesses against a remote service, or uses a built-in password list.

## Run it

Create a wordlist containing candidates you are allowed to test. Generate the target digest with a tool you trust, or use a hash from your own lab. For example, this command creates a SHA-256 digest without putting a fixed password into the program:

```powershell
$target = [Convert]::ToHexString(
  [Security.Cryptography.SHA256]::HashData(
    [Text.Encoding]::UTF8.GetBytes("your-test-value")
  )
).ToLower()
python -m src.cracker $target --wordlist .\words.txt --algorithm sha256
```

The program streams the wordlist, checks each candidate, reports the actual number of candidates examined and measured elapsed time, and stops at the first match. If none of the supplied candidates matches, it reports that result and exits with status 1. It does not invent a recovered value.

Supported algorithms are `md5`, `sha1`, `sha224`, `sha256`, `sha384`, and `sha512`. They are provided for analysis of existing data; SHA-256 or a password-specific KDF is a better choice for new password storage. A general hash is not a password-storage design.

## How it works

`wordlist_candidates()` reads one line at a time, which keeps memory use tied to the current candidate rather than the whole wordlist. `validate_target()` checks the digest length and hexadecimal form before work begins. `digest_text()` encodes each candidate as UTF-8 and uses Python's named hash implementation. `crack_hash()` measures the real duration with a monotonic clock and returns a structured result.

The work is offline and bounded by the wordlist you provide. There is no internet lookup, credential spraying, account lockout risk, or hidden candidate source. A result means only that one supplied candidate matched one supplied digest.

## Scope and authorization

Only test hashes for which you have permission. Do not use recovered values to access another person’s account. The project does not include a remote cracking mode, GPU mode, stealth behavior, or credential exfiltration. A wordlist that contains private passwords should be protected and deleted after the authorized exercise.

## Tests

```console
python -m pytest -q tests
```

The tests use values created inside the test process and do not contain a real account password.
