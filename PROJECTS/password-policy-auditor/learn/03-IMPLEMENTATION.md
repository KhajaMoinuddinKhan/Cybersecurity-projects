# Implementation

- `PROFILES` holds the named profiles, each a title and a tuple of `Requirement` objects.
- A `Requirement` carries a setting, an expected value, a direction (`at_least`, `at_most`, `equals`), a rationale, and optional handling for a missing value or a non-positive bound.
- `_meets()` is the single comparison routine; `evaluate_policy()` applies it to every requirement in a profile.
- `compliance_score()` is the rounded percentage of requirements met.
- `audit_policy()` is kept as a thin wrapper over the baseline profile, so the original interface still works.
- `COMMON_PASSWORDS` and `KEYBOARD_ROWS` back the password checks, and `check_password()` collects every reason a candidate fails.

## Inputs and failure handling

The file uses one `key=value` setting per line. Blank lines and lines beginning with `#` are ignored. Values are integers or `true`/`false`. Use booleans for `require_upper`, `require_lower`, `require_digit` and `require_symbol`, and integers for the numeric settings. A malformed line identifies its line number.

A missing setting fails most requirements, but a profile can name a value to assume instead: NIST treats absent composition rules as `False` and an absent age limit as `0`, so those count as met. The command line exits 0 when all settings pass, 1 when any fails, and 2 on a usage or file error.

The bundled policy is a teaching example; the tool does not read or change Windows, Linux, or directory-service password settings, and it does not read a live directory or credential store.

[Back to the project guide](../README.md)
