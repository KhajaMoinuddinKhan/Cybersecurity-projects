# Architecture

1. The command line accepts a policy file, a `--profile`, an optional `--passwords` list, `--context` terms, and `--json`.
2. `parse_policy()` converts `key=value` text into typed values.
3. `evaluate_policy()` compares each profile requirement with the parsed file and returns a `SettingResult` per setting.
4. `compliance_score()` turns those results into a percentage, and the command line lists the failing settings and sets the exit code.
5. For password mode, `effective_password_rules()` merges the profile with the file, and `check_password()` returns the reasons one candidate fails.

## Follow one run

`parse_policy()` turns the text into typed values. `evaluate_policy()` walks the profile's requirements: minimum length and history as lower bounds, an age limit as a positive upper bound, and character controls as equality against `True` or `False`. Each `SettingResult` carries the actual value, the expected value, the direction, the pass/fail result, and a rationale, which the text formatter prints and the JSON mode serialises.

Password mode reuses the same profile data. `effective_password_rules()` starts from the profile's defaults and lets the policy file override them, then `check_password()` applies length, class, common-password, pattern and context checks to each line of the password list.

The file uses one `key=value` setting per line. Blank lines and lines beginning with `#` are ignored. Values are integers or `true`/`false`. The bundled policy is a teaching example; the tool does not read or change Windows, Linux, or directory-service password settings, and it does not read a live directory or credential store.

[Back to the project guide](../README.md)
