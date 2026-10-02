"""Check a password policy against a small baseline."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

# Baseline values used by this example.
RECOMMENDED = {
    "min_length": 12,
    "require_upper": True,
    "require_lower": True,
    "require_digit": True,
    "require_symbol": True,
    "max_age_days": 90,
    "reuse_limit": 5,
}

@dataclass(frozen=True)
class PolicyCheck:
    """Result for one policy setting."""

    setting: str
    actual: object | None
    recommended: object
    passed: bool
    explanation: str

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

def audit_policy(policy: dict[str, object]) -> list[PolicyCheck]:
    """Compare the policy with the baseline."""

    checks: list[PolicyCheck] = []

    for key, recommended in RECOMMENDED.items():
        actual = policy.get(key)

        # Each numeric setting has a different direction of comparison.
        if key == "min_length":
            passed = (
                isinstance(actual, int)
                and not isinstance(actual, bool)
                and actual >= recommended
            )
            explanation = "The baseline expects a sufficiently long minimum."

        elif key == "max_age_days":
            passed = (
                isinstance(actual, int)
                and not isinstance(actual, bool)
                and 0 < actual <= recommended
            )
            explanation = "The baseline expects a positive age limit at or below this value."

        elif key == "reuse_limit":
            passed = (
                isinstance(actual, int)
                and not isinstance(actual, bool)
                and actual >= recommended
            )
            explanation = (
                "The baseline expects this many or more previous passwords "
                "to be blocked from reuse."
            )

        else:
            passed = actual is recommended
            explanation = "The baseline expects this control to be enabled."

        checks.append(
            PolicyCheck(
                key,
                actual,
                recommended,
                passed,
                explanation,
            )
        )

    return checks

def main() -> None:
    """Read a policy file and print the results."""

    parser = argparse.ArgumentParser(
        description="Audit a password-policy configuration file."
    )
    parser.add_argument("policy", type=Path)
    args = parser.parse_args()

    if not args.policy.is_file():
        raise SystemExit(f"Policy file not found: {args.policy}")

    try:
        checks = audit_policy(parse_policy(args.policy))
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc

    for check in checks:
        status = "PASS" if check.passed else "REVIEW"
        print(
            f"{status:6} {check.setting}: {check.actual!r} "
            f"| baseline={check.recommended!r}"
        )
        if not check.passed:
            print(f"       {check.explanation}")

if __name__ == "__main__":
    main()
