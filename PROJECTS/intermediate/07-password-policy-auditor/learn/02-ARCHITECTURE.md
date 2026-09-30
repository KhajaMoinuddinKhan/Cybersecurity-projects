# Architecture

1. The command line accepts a local policy file.
2. `parse_policy()` converts `key=value` text into typed values.
3. `audit_policy()` compares each supported field with the baseline.
4. `PolicyCheck` records the actual value, reference value, status, and explanation.
5. The command line prints the result for every supported setting.
