# Password Policy Auditor

Every organisation has a password policy. Fewer have one that matches the number written in the document everyone was given. This tool reads a small key=value policy file and compares it, field by field, against a baseline defined in the code, printing one line per setting.

The result is a short table you can paste into a review, with the actual value, the expected value, and a verdict.

## Running it

Standard library only:

```console
python -m src.audit sample_policy.conf
```

The bundled fixture passes every check:

```
PASS   min_length: 12 | baseline=12
PASS   require_upper: True | baseline=True
PASS   require_lower: True | baseline=True
PASS   require_digit: True | baseline=True
PASS   require_symbol: True | baseline=True
PASS   max_age_days: 90 | baseline=90
PASS   reuse_limit: 5 | baseline=5
```

Change `min_length=12` to `min_length=8` and that line becomes a `FAIL` with both numbers shown, which is the whole point: the comparison is explicit, so nobody has to trust a summary.

## The file format

One `key=value` per line. Blank lines are ignored, keys are case-insensitive, and a duplicate key keeps the last value. A UTF-8 byte order mark at the start of the file is tolerated, because editors add one without asking.

Values are typed before comparison. `true` and `false` become booleans, digits become integers, and anything else stays text. An unknown setting is reported with its line number rather than ignored, and a value of the wrong type for a known setting is called out rather than compared as text against a number.

## Where the baseline lives

The expected values are defined in the code, which makes them easy to read, review and disagree with. That is deliberate for a teaching tool and wrong for a real deployment: a production auditor should read the expected values from the same place the policy is actually enforced, so the two cannot drift apart. If you extend this project, that is the first thing to change.

## What it checks

Minimum length, upper/lower/digit/symbol requirements, maximum age in days, and password reuse limit. It does not read a domain controller, a PAM configuration, or an identity provider. It audits the file you gave it, and only that file.

## Tests

```console
python -m pytest -q tests
```

Tests cover baseline comparisons, wrong types, unknown settings with line numbers, duplicate keys, and a policy file saved with a byte order mark.
