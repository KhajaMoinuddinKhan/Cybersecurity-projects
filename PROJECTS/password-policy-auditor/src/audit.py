"""Audit a password policy against a named profile and check candidate passwords.

The policy audit reads a small ``key=value`` file and evaluates it against a
named profile: the project baseline, NIST SP 800-63B, the CIS Windows
benchmark, or PCI-DSS. It prints which settings the file meets, which it does
not, and a compliance score as a percentage.

The password audit reads a list of candidate passwords you supply and checks
each one against the effective policy, reporting the passwords that fail and
the specific reason for each: too short, a missing character class, a known
common password, a simple pattern, or a context term such as an account or
company name.

Both modes print a human-readable report or, with ``--json``, a JSON document.
Neither mode reads a live directory, a credential store, or an enforced
operating-system policy. The tool audits the files you give it, and only those
files.
"""
from __future__ import annotations

import argparse
import itertools
import json
import sys
from dataclasses import dataclass
from pathlib import Path


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Requirement:
    """One setting a profile expects, and how the policy file should compare.

    ``direction`` is one of ``at_least``, ``at_most`` or ``equals``.
    ``positive_only`` additionally rejects zero for an ``at_most`` bound.
    ``missing_default`` is the value assumed when the setting is absent; when
    it is ``None`` an absent setting fails the requirement.
    """

    setting: str
    expected: object
    direction: str
    rationale: str
    positive_only: bool = False
    missing_default: object | None = None


@dataclass(frozen=True)
class Profile:
    """A named set of requirements with a human-readable title."""

    title: str
    requirements: tuple[Requirement, ...]


def _boolean(
    name: str,
    expected: bool,
    rationale: str,
    *,
    missing_default: object | None = None,
) -> Requirement:
    """Build an ``equals`` requirement for a boolean control."""

    return Requirement(
        name,
        expected,
        "equals",
        rationale,
        missing_default=missing_default,
    )


# The original project baseline. Kept so the first version of the tool still
# behaves exactly as it did: length 12, four character classes, an age limit of
# 90 days, and five remembered passwords.
_BASELINE = Profile(
    "Project baseline",
    (
        Requirement(
            "min_length",
            12,
            "at_least",
            "The baseline expects a sufficiently long minimum.",
        ),
        _boolean("require_upper", True, "The baseline expects this control to be enabled."),
        _boolean("require_lower", True, "The baseline expects this control to be enabled."),
        _boolean("require_digit", True, "The baseline expects this control to be enabled."),
        _boolean("require_symbol", True, "The baseline expects this control to be enabled."),
        Requirement(
            "max_age_days",
            90,
            "at_most",
            "The baseline expects a positive age limit at or below this value.",
            positive_only=True,
        ),
        Requirement(
            "reuse_limit",
            5,
            "at_least",
            "The baseline expects this many or more previous passwords "
            "to be blocked from reuse.",
        ),
    ),
)

# NIST SP 800-63B (revision 3, 2017). The modern guidance is deliberately at
# odds with the older baseline: a short minimum length, no forced composition,
# and no mandatory periodic expiry. Absent composition rules and an absent or
# zero age limit are therefore compliant, not missing.
_NIST = Profile(
    "NIST SP 800-63B",
    (
        Requirement(
            "min_length",
            8,
            "at_least",
            "NIST SP 800-63B 5.1.1.1 requires a minimum length of 8 characters "
            "(and recommends permitting at least 64).",
        ),
        _boolean(
            "require_upper",
            False,
            "NIST SP 800-63B 5.1.1.2 says verifiers SHOULD NOT impose composition "
            "rules such as requiring mixed case.",
            missing_default=False,
        ),
        _boolean(
            "require_lower",
            False,
            "NIST SP 800-63B 5.1.1.2 says verifiers SHOULD NOT impose composition "
            "rules such as requiring mixed case.",
            missing_default=False,
        ),
        _boolean(
            "require_digit",
            False,
            "NIST SP 800-63B 5.1.1.2 says verifiers SHOULD NOT impose composition "
            "rules such as requiring digits.",
            missing_default=False,
        ),
        _boolean(
            "require_symbol",
            False,
            "NIST SP 800-63B 5.1.1.2 says verifiers SHOULD NOT impose composition "
            "rules such as requiring special characters.",
            missing_default=False,
        ),
        Requirement(
            "max_age_days",
            0,
            "at_most",
            "NIST SP 800-63B 5.1.1.2 says verifiers SHOULD NOT require memorized "
            "secrets to be changed arbitrarily (no periodic expiry).",
            missing_default=0,
        ),
    ),
)

# CIS Microsoft Windows 10/11 Benchmark, Account Policies - Password Policy.
_CIS = Profile(
    "CIS Windows Benchmark",
    (
        Requirement(
            "min_length",
            14,
            "at_least",
            "CIS Windows benchmarks require a minimum password length of 14 characters.",
        ),
        _boolean(
            "require_upper",
            True,
            "CIS requires password complexity to be enabled (Windows counts at "
            "least three of the four character classes).",
        ),
        _boolean(
            "require_lower",
            True,
            "CIS requires password complexity to be enabled (Windows counts at "
            "least three of the four character classes).",
        ),
        _boolean(
            "require_digit",
            True,
            "CIS requires password complexity to be enabled (Windows counts at "
            "least three of the four character classes).",
        ),
        _boolean(
            "require_symbol",
            True,
            "CIS requires password complexity to be enabled (Windows counts at "
            "least three of the four character classes).",
        ),
        Requirement(
            "max_age_days",
            365,
            "at_most",
            "CIS requires a maximum password age of 365 days or fewer, but not 0.",
            positive_only=True,
        ),
        Requirement(
            "reuse_limit",
            24,
            "at_least",
            "CIS requires a password history of 24 or more remembered passwords.",
        ),
    ),
)

# PCI-DSS v4.0, requirement 8.3.
_PCI = Profile(
    "PCI-DSS v4.0",
    (
        Requirement(
            "min_length",
            12,
            "at_least",
            "PCI-DSS v4.0 8.3.6 requires a minimum password length of 12 characters.",
        ),
        _boolean("require_upper", True, "PCI-DSS 8.3.6 requires complexity: a mix of character types."),
        _boolean("require_lower", True, "PCI-DSS 8.3.6 requires complexity: a mix of character types."),
        _boolean("require_digit", True, "PCI-DSS 8.3.6 requires complexity: a mix of character types."),
        _boolean("require_symbol", True, "PCI-DSS 8.3.6 requires complexity: a mix of character types."),
        Requirement(
            "max_age_days",
            90,
            "at_most",
            "PCI-DSS 8.3.9 requires passwords to change at least every 90 days "
            "unless MFA is used.",
            positive_only=True,
        ),
        Requirement(
            "reuse_limit",
            4,
            "at_least",
            "PCI-DSS 8.3.7 requires blocking reuse of the last 4 passwords.",
        ),
    ),
)

PROFILES: dict[str, Profile] = {
    "baseline": _BASELINE,
    "nist": _NIST,
    "cis": _CIS,
    "pci": _PCI,
}

# The baseline's expected values, kept under its original name for anything
# that still imports it.
RECOMMENDED: dict[str, object] = {
    requirement.setting: requirement.expected
    for requirement in _BASELINE.requirements
}


# ---------------------------------------------------------------------------
# Common passwords and pattern detection
# ---------------------------------------------------------------------------

# A short, illustrative list of very common passwords. This is deliberately
# small: it is a teaching sample, not a breach corpus. A production tool should
# check against a large breached-password list (for example a top-million
# list, or an API such as Have I Been Pwned's k-anonymity range search).
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "123456", "password", "123456789", "12345678", "12345", "1234567",
        "qwerty", "abc123", "111111", "123123", "admin", "letmein", "welcome",
        "monkey", "dragon", "master", "login", "passw0rd", "password1",
        "qwerty123", "1q2w3e4r", "iloveyou", "sunshine", "princess",
        "football", "baseball", "shadow", "superman", "michael", "trustno1",
        "000000", "654321", "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "password123", "admin123", "root", "toor", "guest", "changeme",
        "changeme123", "access", "flower", "whatever", "hello123", "freedom",
    }
)

# Keyboard rows used for the keyboard-run pattern check. Each is a contiguous
# slice of a physical row, so a run such as "asdf" or "qwer" is recognised.
KEYBOARD_ROWS: tuple[str, ...] = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "1qaz2wsx",
    "qazwsxedc",
)


# ---------------------------------------------------------------------------
# Parsing and profile evaluation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyCheck:
    """Result for one policy setting (the original baseline interface)."""

    setting: str
    actual: object | None
    recommended: object
    passed: bool
    explanation: str


@dataclass(frozen=True)
class SettingResult:
    """Result for one setting of a named profile."""

    setting: str
    actual: object | None
    expected: object
    direction: str
    passed: bool
    rationale: str
    present: bool


def parse_policy(path: Path) -> dict[str, object]:
    """Read a key=value policy file."""

    values: dict[str, object] = {}

    for line_number, line in enumerate(
        path.read_text(encoding="utf-8-sig").splitlines(),
        1,
    ):
        stripped = line.strip()

        # Blank lines and file comments can be ignored.
        if not stripped or stripped.startswith("#"):
            continue

        if "=" not in stripped:
            raise ValueError(f"Line {line_number}: expected key=value")

        key, value = (part.strip() for part in stripped.split("=", 1))
        # Keys are documented as case-insensitive, so normalise before lookup.
        key = key.lower()
        lowered = value.lower()

        if lowered in {"true", "false"}:
            values[key] = lowered == "true"
        else:
            try:
                values[key] = int(value)
            except ValueError as exc:
                raise ValueError(
                    f"Line {line_number}: unsupported value for {key!r}"
                ) from exc

        if key not in RECOMMENDED:
            raise ValueError(f"Line {line_number}: unknown setting {key!r}")
    return values


def _meets(actual: object | None, requirement: Requirement) -> bool:
    """Return whether one parsed value satisfies one requirement."""

    if actual is None:
        if requirement.missing_default is None:
            return False
        actual = requirement.missing_default

    if requirement.direction == "equals":
        # ``is`` keeps a real boolean distinct from the integer 1.
        return actual is requirement.expected

    if not isinstance(actual, int) or isinstance(actual, bool):
        return False
    if requirement.positive_only and actual <= 0:
        return False
    if requirement.direction == "at_least":
        return actual >= requirement.expected
    if requirement.direction == "at_most":
        return actual <= requirement.expected
    raise ValueError(f"Unknown comparison direction: {requirement.direction!r}")


def evaluate_policy(
    policy: dict[str, object],
    profile: str = "baseline",
) -> list[SettingResult]:
    """Evaluate a parsed policy against a named profile."""

    results: list[SettingResult] = []

    for requirement in PROFILES[profile].requirements:
        actual = policy.get(requirement.setting)
        results.append(
            SettingResult(
                requirement.setting,
                actual,
                requirement.expected,
                requirement.direction,
                _meets(actual, requirement),
                requirement.rationale,
                requirement.setting in policy,
            )
        )

    return results


def compliance_score(results: list[SettingResult]) -> int:
    """Return the percentage of settings met, rounded to a whole number."""

    if not results:
        return 100
    met = sum(1 for result in results if result.passed)
    return round(100 * met / len(results))


def audit_policy(policy: dict[str, object]) -> list[PolicyCheck]:
    """Compare the policy with the project baseline (the original interface)."""

    return [
        PolicyCheck(
            result.setting,
            result.actual,
            result.expected,
            result.passed,
            result.rationale,
        )
        for result in evaluate_policy(policy, "baseline")
    ]


# ---------------------------------------------------------------------------
# Password auditing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PasswordRules:
    """The subset of policy settings that apply to a single password."""

    min_length: int
    require_upper: bool
    require_lower: bool
    require_digit: bool
    require_symbol: bool


def effective_password_rules(
    policy: dict[str, object],
    profile: str = "baseline",
) -> PasswordRules:
    """Merge a profile's defaults with any matching settings in the policy file.

    Settings present in the file win, so the effective rules describe the
    policy as written rather than the profile in the abstract.
    """

    requirements = {req.setting: req for req in PROFILES[profile].requirements}

    def default_for(name: str, fallback: object) -> object:
        requirement = requirements.get(name)
        return requirement.expected if requirement is not None else fallback

    values: dict[str, object] = {
        "min_length": default_for("min_length", 8),
        "require_upper": bool(default_for("require_upper", False)),
        "require_lower": bool(default_for("require_lower", False)),
        "require_digit": bool(default_for("require_digit", False)),
        "require_symbol": bool(default_for("require_symbol", False)),
    }

    min_length = policy.get("min_length")
    if isinstance(min_length, int) and not isinstance(min_length, bool):
        values["min_length"] = min_length
    for name in ("require_upper", "require_lower", "require_digit", "require_symbol"):
        if isinstance(policy.get(name), bool):
            values[name] = policy[name]

    return PasswordRules(**values)  # type: ignore[arg-type]


def _has_repeated_run(text: str, run: int = 3) -> bool:
    """True when any single character repeats ``run`` or more times in a row."""

    return any(len(list(group)) >= run for _, group in itertools.groupby(text))


def _has_sequential_run(text: str, run: int = 4) -> bool:
    """True for a run of ``run`` consecutive ascending or descending characters."""

    for start in range(len(text) - run + 1):
        chunk = text[start:start + run]
        steps = [ord(chunk[i + 1]) - ord(chunk[i]) for i in range(run - 1)]
        if all(step == 1 for step in steps) or all(step == -1 for step in steps):
            return True
    return False


def _has_keyboard_run(text: str, run: int = 4) -> bool:
    """True for a run of ``run`` characters adjacent on a keyboard row."""

    for row in KEYBOARD_ROWS:
        for start in range(len(row) - run + 1):
            segment = row[start:start + run]
            if segment in text or segment[::-1] in text:
                return True
    return False


def _pattern_reasons(password: str) -> list[str]:
    """Return the simple-pattern reasons a password trips, if any."""

    text = password.lower()
    reasons: list[str] = []
    if _has_repeated_run(text):
        reasons.append("contains a repeated character run")
    if _has_sequential_run(text):
        reasons.append("contains a sequential string")
    if _has_keyboard_run(text):
        reasons.append("contains a keyboard run")
    return reasons


def check_password(
    password: str,
    rules: PasswordRules,
    context: list[str] | None = None,
) -> list[str]:
    """Return every reason this password fails the effective policy.

    An empty list means the password passed every check.
    """

    reasons: list[str] = []

    if len(password) < rules.min_length:
        reasons.append(f"too short ({len(password)} < {rules.min_length})")

    classes = (
        ("uppercase", rules.require_upper, any(c.isupper() for c in password)),
        ("lowercase", rules.require_lower, any(c.islower() for c in password)),
        ("digit", rules.require_digit, any(c.isdigit() for c in password)),
        ("symbol", rules.require_symbol, any(not c.isalnum() for c in password)),
    )
    for label, required, present in classes:
        if required and not present:
            reasons.append(f"missing required {label}")

    if password.lower() in COMMON_PASSWORDS:
        reasons.append("is a known common password")

    reasons.extend(_pattern_reasons(password))

    for term in context or []:
        if term and term.lower() in password.lower():
            reasons.append(f"contains context term {term!r}")

    return reasons


def _read_passwords(path: Path) -> list[str]:
    """Read one candidate password per line, ignoring blank lines."""

    text = path.read_text(encoding="utf-8-sig")
    return [line for line in text.splitlines() if line != ""]


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit a password policy and check a list of candidate passwords."
    )
    parser.add_argument(
        "policy",
        nargs="?",
        type=Path,
        help="policy file to audit (one key=value per line)",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default="baseline",
        help="policy profile to evaluate against (default: baseline)",
    )
    parser.add_argument(
        "--passwords",
        type=Path,
        metavar="FILE",
        help="audit a list of candidate passwords, one per line",
    )
    parser.add_argument(
        "--context",
        action="append",
        default=[],
        metavar="NAME",
        help="account or company name to flag inside passwords (repeatable)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a JSON report instead of text",
    )
    return parser


def _setting_dict(result: SettingResult) -> dict[str, object]:
    return {
        "setting": result.setting,
        "actual": result.actual if result.present else None,
        "present": result.present,
        "expected": result.expected,
        "direction": result.direction,
        "passed": result.passed,
        "rationale": result.rationale,
    }


def _format_setting_line(result: SettingResult, label: str) -> str:
    status = "PASS" if result.passed else "FAIL"
    actual = repr(result.actual) if result.present else "not set"
    return f"{status:6} {result.setting}: {actual} | {label}={result.expected!r}"


def _rules_text(rules: PasswordRules) -> str:
    required = [
        name.replace("require_", "")
        for name in ("require_upper", "require_lower", "require_digit", "require_symbol")
        if getattr(rules, name)
    ]
    return f"min_length={rules.min_length}, required classes: {', '.join(required) or 'none'}"


def _policy_audit(args: argparse.Namespace) -> int:
    if not args.policy.is_file():
        print(f"Policy file not found: {args.policy}", file=sys.stderr)
        return 2
    try:
        policy = parse_policy(args.policy)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    profile = PROFILES[args.profile]
    results = evaluate_policy(policy, args.profile)
    score = compliance_score(results)
    failing = [result.setting for result in results if not result.passed]
    met = len(results) - len(failing)

    if args.json:
        print(
            json.dumps(
                {
                    "mode": "policy",
                    "profile": args.profile,
                    "profile_title": profile.title,
                    "score": score,
                    "met": met,
                    "total": len(results),
                    "passed": not failing,
                    "failing": failing,
                    "settings": [_setting_dict(result) for result in results],
                },
                indent=2,
            )
        )
        return 1 if failing else 0

    label = "baseline" if args.profile == "baseline" else "expected"
    print(f"Profile: {profile.title}")
    for result in results:
        print(_format_setting_line(result, label))
        if not result.passed:
            print(f"       {result.rationale}")
    print(f"Compliance: {score}% ({met} of {len(results)} settings met)")
    print("Failing settings: " + (", ".join(failing) if failing else "none"))
    return 1 if failing else 0


def _password_audit(args: argparse.Namespace) -> int:
    policy: dict[str, object] = {}
    if args.policy is not None:
        if not args.policy.is_file():
            print(f"Policy file not found: {args.policy}", file=sys.stderr)
            return 2
        try:
            policy = parse_policy(args.policy)
        except (OSError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2

    if not args.passwords.is_file():
        print(f"Password list not found: {args.passwords}", file=sys.stderr)
        return 2
    try:
        passwords = _read_passwords(args.passwords)
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    profile = PROFILES[args.profile]
    rules = effective_password_rules(policy, args.profile)
    context = [term for term in args.context if term]
    results = [(pwd, check_password(pwd, rules, context)) for pwd in passwords]
    failed = [pwd for pwd, reasons in results if reasons]

    if args.json:
        print(
            json.dumps(
                {
                    "mode": "passwords",
                    "profile": args.profile,
                    "profile_title": profile.title,
                    "context": context,
                    "rules": {
                        "min_length": rules.min_length,
                        "require_upper": rules.require_upper,
                        "require_lower": rules.require_lower,
                        "require_digit": rules.require_digit,
                        "require_symbol": rules.require_symbol,
                    },
                    "total": len(passwords),
                    "failed": len(failed),
                    "passwords": [
                        {"password": pwd, "passed": not reasons, "reasons": reasons}
                        for pwd, reasons in results
                    ],
                },
                indent=2,
            )
        )
        return 1 if failed else 0

    print(f"Profile: {profile.title}")
    print(f"Effective rules: {_rules_text(rules)}")
    if context:
        print("Context terms: " + ", ".join(context))
    print()
    for pwd, reasons in results:
        if reasons:
            print(f"FAIL   {pwd!r}: " + "; ".join(reasons))
        else:
            print(f"PASS   {pwd!r}")
    print()
    print(
        f"Summary: {len(passwords) - len(failed)} of {len(passwords)} candidate "
        f"passwords passed; {len(failed)} failed."
    )
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    """Run the command line and return the process exit code."""

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.passwords is not None:
        return _password_audit(args)

    if args.policy is None:
        parser.error("provide a policy file or --passwords")

    return _policy_audit(args)


if __name__ == "__main__":
    raise SystemExit(main())
