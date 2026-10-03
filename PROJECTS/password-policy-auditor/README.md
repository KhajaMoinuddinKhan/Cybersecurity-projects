# Password Policy Auditor

Every organisation has a password policy. Fewer have one that matches the number written in the document everyone was given. This tool reads a small key=value policy file, evaluates it against a named policy profile, and prints one line per setting with the actual value, the expected value, and a verdict. It can also read a list of candidate passwords and report which ones the policy would reject, and why.

The result is a short table you can paste into a review, a compliance score, and, in password mode, a per-password explanation.

## Running it

Standard library only.

Audit a policy file against a profile. The default profile is the project baseline:

```console
python -m src.audit sample_policy.conf
```

```
Profile: Project baseline
PASS   min_length: 12 | baseline=12
PASS   require_upper: True | baseline=True
PASS   require_lower: True | baseline=True
PASS   require_digit: True | baseline=True
PASS   require_symbol: True | baseline=True
PASS   max_age_days: 90 | baseline=90
PASS   reuse_limit: 5 | baseline=5
Compliance: 100% (7 of 7 settings met)
Failing settings: none
```

The same file scores 17% under NIST SP 800-63B, because NIST advises against composition rules and mandatory expiry:

```console
python -m src.audit sample_policy.conf --profile nist
```

```
Profile: NIST SP 800-63B
PASS   min_length: 12 | expected=8
FAIL   require_upper: True | expected=False
       NIST SP 800-63B 5.1.1.2 says verifiers SHOULD NOT impose composition rules such as requiring mixed case.
FAIL   require_lower: True | expected=False
       NIST SP 800-63B 5.1.1.2 says verifiers SHOULD NOT impose composition rules such as requiring mixed case.
FAIL   require_digit: True | expected=False
       NIST SP 800-63B 5.1.1.2 says verifiers SHOULD NOT impose composition rules such as requiring digits.
FAIL   require_symbol: True | expected=False
       NIST SP 800-63B 5.1.1.2 says verifiers SHOULD NOT impose composition rules such as requiring special characters.
FAIL   max_age_days: 90 | expected=0
       NIST SP 800-63B 5.1.1.2 says verifiers SHOULD NOT require memorized secrets to be changed arbitrarily (no periodic expiry).
Compliance: 17% (1 of 6 settings met)
Failing settings: require_upper, require_lower, require_digit, require_symbol, max_age_days
```

The process exit code is 0 when every setting is met and 1 when any setting fails, so the tool drops straight into a CI check. A usage or file error exits 2.

## Profiles

`--profile` selects one of four named profiles:

- `baseline` - the original project baseline: length 12, four character classes, an age limit of 90 days, and a history of 5.
- `nist` - NIST SP 800-63B: minimum length 8, no composition rules, no periodic expiry.
- `cis` - CIS Windows benchmark: length 14, complexity enabled, an age limit of 365 days, and a history of 24.
- `pci` - PCI-DSS v4.0: length 12, complexity, an age limit of 90 days, and reuse of the last 4 passwords blocked.

Each profile encodes those values as explicit requirements, each with a comparison direction and a rationale. The report shows which of the profile's settings the file meets and which it does not.

NIST is the odd one out on purpose. Where the baseline and CIS/PCI ask for composition rules and an age limit, NIST says a verifier SHOULD NOT impose them. Under `--profile nist`, an absent composition rule or an absent age limit is compliant, not missing. That disagreement is the clearest reason a single invented baseline is not enough.

## Auditing passwords

`--passwords FILE` reads one candidate password per line (blank lines are ignored) and checks each against the effective policy:

```console
python -m src.audit sample_policy.conf --passwords sample_passwords.txt --context acme
```

```
Profile: Project baseline
Effective rules: min_length=12, required classes: upper, lower, digit, symbol
Context terms: acme

FAIL   'Ab1!Ab1!': too short (8 < 12)
FAIL   'lowercaseonly': missing required uppercase; missing required digit; missing required symbol
FAIL   'zxcvbnmZX1!a': contains a keyboard run
FAIL   'aaaaaaaaAa1!': contains a repeated character run
FAIL   'abcdefghW1!q': contains a sequential string
FAIL   'Acme-Corp-2024': contains context term 'acme'
PASS   'Tr0ub4dor&3xY'

Summary: 1 of 7 candidate passwords passed; 6 failed.
```

A password is reported with every reason it trips:

- **too short** - fewer characters than the effective minimum length.
- **missing a required class** - a required uppercase, lowercase, digit or symbol character is absent.
- **a known common password** - the password (lowercased) appears in the embedded list.
- **a simple pattern** - a run of three or more identical characters, a run of four consecutive characters such as `abcd` or `4321`, or a run of four adjacent keyboard characters such as `qwer` or `zxcv`.
- **a context term** - the password contains an account or company name supplied with `--context` (case-insensitive). `--context` can be repeated.

The effective policy is the selected profile, overridden by any settings present in the policy file. With no policy file, the profile's own values are used. Under `--profile nist`, no character classes are required, so `Ab1!Ab1!` passes there but fails the baseline. Password mode exits 0 when every candidate passed and 1 when any failed.

## JSON output

`--json` prints the result as a JSON document in both modes.

```console
python -m src.audit sample_policy.conf --profile nist --json
```

```json
{
  "mode": "policy",
  "profile": "nist",
  "profile_title": "NIST SP 800-63B",
  "score": 17,
  "met": 1,
  "total": 6,
  "passed": false,
  "failing": ["require_upper", "require_lower", "require_digit", "require_symbol", "max_age_days"],
  "settings": [{"setting": "min_length", "actual": 12, "present": true, "expected": 8, "direction": "at_least", "passed": true, "rationale": "NIST SP 800-63B 5.1.1.1 requires a minimum length of 8 characters (and recommends permitting at least 64)."}]
}
```

Password mode emits `{"mode": "passwords", "rules": {...}, "passwords": [{"password": "...", "passed": false, "reasons": [...]}], "total": ..., "failed": ...}`. The JSON contains the candidate passwords you supplied, in plain text.

## The file format

One `key=value` per line. Blank lines are ignored, keys are case-insensitive, and a duplicate key keeps the last value. A UTF-8 byte order mark at the start of the file is tolerated, because editors add one without asking.

Values are typed before comparison. `true` and `false` become booleans, digits become integers, and anything else is rejected. An unknown setting is reported with its line number rather than ignored, and a value of the wrong type for a known setting is called out rather than compared as text.

## Where the profile values live

The expected values for each profile are defined in the code, which makes them easy to read, review and disagree with. That is deliberate for a teaching tool and wrong for a real deployment: a production auditor should read the expected values from the same place the policy is actually enforced, so the two cannot drift apart. If you extend this project, that is the first thing to change.

The profile values are a reading of each standard's published recommendations, not a certification. See Limits.

## The common-password list

The embedded common-password list is a short illustrative sample of a few dozen entries, not a breach corpus. It exists to show the check working. A real deployment should check against a large breached-password corpus, for example a top-million list or the Have I Been Pwned range API. Treating a password that is absent from this list as safe would be a mistake.

## Limits

- The policy audit reads the file you gave it and compares it with a profile. It does not read a domain controller, a PAM configuration, an identity provider, or any enforced operating-system setting, and it does not change anything.
- The profile values are a teaching reading of the standards, not a compliance certification. Standards carry nuances this model simplifies - Windows counts three of the four character classes for "complexity", and PCI-DSS 8.3.9 permits MFA instead of rotation. Read the current text of each standard before relying on this.
- The common-password list is a tiny illustrative sample, not a complete breach corpus.
- The password mode checks a list of candidate passwords you supply. It does not read a live directory, a credential store, or any account, and it cannot tell you which passwords real users have chosen.
- The pattern checks are simple heuristics (runs of identical characters, sequential strings, keyboard rows). They will miss many weak passwords and flag some strong ones.
- A passing password here does not measure real-world strength, MFA, breach exposure, or account recovery.

## Tests

```console
python -m pytest -q tests
```

Tests cover baseline comparisons, profile evaluation (NIST, CIS, PCI-DSS), compliance scoring and the exit code, JSON output in both modes, and every password failure reason including the context check, plus wrong types, unknown settings with line numbers, duplicate keys, and a policy file saved with a byte order mark.
