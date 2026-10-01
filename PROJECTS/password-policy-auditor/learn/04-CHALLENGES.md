# Challenges

- The baseline is a project choice and is not a universal policy standard.
- The parser accepts only simple integer and boolean values.
- The project reads a local configuration file rather than an operating-system policy source.
- A passing setting does not describe the strength of user-selected passwords.

## Working within the scope

The baseline is an illustrative project choice, not a claim of compliance or current best practice. It uses length 12, four character-class requirements, a maximum age of 90 days, and reuse history of 5. Choose a real policy separately for your environment; a passing result here does not measure password strength, MFA, breach detection, or account recovery.

Run the supplied policy, then lower `reuse_limit` to 3 in a copy. Only that setting should change to review if the other values stay the same. This illustrates why different policy fields need different comparison directions, rather than one generic greater-than check.

[Back to the project guide](../README.md)
