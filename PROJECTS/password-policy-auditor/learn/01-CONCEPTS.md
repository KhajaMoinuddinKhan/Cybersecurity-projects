# Concepts

- A profile is a named set of requirements, each with a value, a comparison direction, and a rationale.
- Comparison direction matters: minimum length and password history are lower bounds, an age limit is an upper bound, and a boolean control is an equality.
- Absence is not always failure. NIST asks for no composition rules and no periodic expiry, so omitting those settings is compliant, while the baseline treats a missing control as a failure.
- A compliance score is the percentage of a profile's settings the file meets, and the failing settings are listed beside it.
- A password check applies the effective policy to one candidate: length, character classes, the common-password list, simple patterns, and context terms.

## Interpreting the evidence

Each setting is printed as `PASS` or `FAIL`, with its actual value, the profile's expected value, and a rationale on failure. The compliance score and the list of failing settings summarise the run, and the process exit code is non-zero when anything fails.

In password mode each candidate is printed with every reason it trips, and the summary counts how many passed. The effective policy is the selected profile overridden by any settings in the policy file.

The profiles are a reading of each standard's published recommendations, not a claim of compliance or current best practice. A passing result here does not measure password strength, MFA, breach detection, or account recovery.

[Back to the project guide](../README.md)
