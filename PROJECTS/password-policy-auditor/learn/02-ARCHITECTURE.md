# Architecture

1. The command line accepts a local policy file.
2. `parse_policy()` converts `key=value` text into typed values.
3. `audit_policy()` compares each supported field with the baseline.
4. `PolicyCheck` records the actual value, reference value, status, and explanation.
5. The command line prints the result for every supported setting.

## Follow one run

`parse_policy()` turns the text into typed values. `audit_policy()` checks minimum length and reuse history as lower bounds, password age as a positive upper bound, and character requirements as explicit booleans. `PolicyCheck` carries the result and its explanation to the command-line formatter.

The file uses one `key=value` setting per line. Blank lines and lines beginning with `#` are ignored. Values are integers or `true`/`false`. The bundled policy is a teaching example; the tool does not read or change Windows, Linux, or directory-service password settings.

[Back to the project guide](../README.md)
