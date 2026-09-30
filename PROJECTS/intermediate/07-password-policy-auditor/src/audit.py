"""Check a password-policy configuration against a visible baseline."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path


# [SECTION] Visible baseline
# The values are intentionally defined in one place so a reviewer can see exactly
# what the learning tool considers acceptable rather than relying on hidden logic.
RECOMMENDED = {
    "min_length": 12,
    "require_upper": True,
    "require_lower": True,
    "require_digit": True,
    "require_symbol": True,
    "max_age_days": 90,
    "reuse_limit": 5,
}


# [SECTION] Audit result model
@dataclass(frozen=True)
class PolicyCheck:
    """Describe the result of checking one password-policy setting."""

    setting: str
    actual: object | None
    recommended: object
    passed: bool
    explanation: str


# [SECTION] Policy parser
def parse_policy(path: Path) -> dict[str, object]:
    """Parse a simple key=value policy file into typed Python values."""

    values: dict[str, object] = {}

    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        1,
    ):
        stripped = line.strip()

        # Ignore blank lines and comments so the file stays readable for humans.
        if not stripped or stripped.startswith("#"):
            continue

        if "=" not in stripped:
            raise ValueError(f"Line {line_number}: expected key=value")

        key, value = (part.strip() for part in stripped.split("=", 1))
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

    return values


# [SECTION] Baseline comparison
def audit_policy(policy: dict[str, object]) -> list[PolicyCheck]:
    """Compare each supported policy setting against the visible baseline."""

    checks: list[PolicyCheck] = []

    for key, recommended in RECOMMENDED.items():
        actual = policy.get(key)

        # Minimum length becomes stronger as the configured number increases.
        if key == "min_length":
            passed = (
                isinstance(actual, int)
                and not isinstance(actual, bool)
                and actual >= recommended
            )
            explanation = "The baseline expects a sufficiently long minimum."

        # Maximum age becomes stricter as the allowed number of days decreases.
        elif key == "max_age_days":
            passed = (
                isinstance(actual, int)
                and not isinstance(actual, bool)
                and 0 < actual <= recommended
            )
            explanation = "The baseline expects a positive age limit at or below this value."

        # A larger history blocks more previously used passwords from being reused.
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

        # Boolean controls must be explicitly enabled rather than merely truthy.
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


# [SECTION] Command-line interface
def main() -> None:
    """Read a policy file, run the checks, and print PASS/REVIEW results."""

    parser = argparse.ArgumentParser(
        description="Audit a password-policy configuration file."
    )
    parser.add_argument("policy", type=Path)
    args = parser.parse_args()

    if not args.policy.is_file():
        raise SystemExit(f"Policy file not found: {args.policy}")

    try:
        checks = audit_policy(parse_policy(args.policy))
    except ValueError as exc:
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
