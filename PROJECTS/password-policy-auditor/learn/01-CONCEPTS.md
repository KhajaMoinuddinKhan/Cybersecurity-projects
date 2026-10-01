# Concepts

- A policy baseline gives each supported setting an explicit reference value.
- Minimum length becomes stronger as the configured value increases.
- Maximum age uses an upper limit, while reuse history uses a lower limit.
- Boolean controls must be enabled explicitly.
- Typed parsing keeps numeric and boolean settings distinct.

## Interpreting the evidence

Each setting is printed as `PASS` or `REVIEW`, alongside its actual value and the example baseline. Missing settings are reviewed rather than assumed to be enabled. A run that reports review items can still finish successfully: the exit status indicates whether the file was processed, not whether every setting passed.

The baseline is an illustrative project choice, not a claim of compliance or current best practice. It uses length 12, four character-class requirements, a maximum age of 90 days, and reuse history of 5. Choose a real policy separately for your environment; a passing result here does not measure password strength, MFA, breach detection, or account recovery.

[Back to the project guide](../README.md)
