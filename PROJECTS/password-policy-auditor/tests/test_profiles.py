"""Profile evaluation: the baseline, NIST SP 800-63B, CIS and PCI-DSS."""
from src.audit import audit_policy, evaluate_policy


def _by_setting(policy, profile):
    return {result.setting: result for result in evaluate_policy(policy, profile)}


def test_baseline_profile_matches_the_original_audit():
    policy = {
        "min_length": 12, "require_upper": True, "require_lower": True,
        "require_digit": True, "require_symbol": True,
        "max_age_days": 90, "reuse_limit": 5,
    }
    assert all(result.passed for result in evaluate_policy(policy, "baseline"))
    assert all(check.passed for check in audit_policy(policy))


def test_nist_profile_rejects_composition_and_forced_expiry():
    # NIST SP 800-63B advises against composition rules and periodic expiry,
    # so a policy that imposes both fails even though the baseline passes it.
    policy = {
        "min_length": 12, "require_upper": True, "require_lower": True,
        "require_digit": True, "require_symbol": True,
        "max_age_days": 90, "reuse_limit": 5,
    }
    results = _by_setting(policy, "nist")
    assert results["min_length"].passed is True
    assert results["require_upper"].passed is False
    assert results["require_symbol"].passed is False
    assert results["max_age_days"].passed is False


def test_nist_profile_accepts_absent_composition_and_expiry():
    # A policy that simply omits composition rules and an age limit is exactly
    # what NIST asks for, so absence is compliant rather than missing.
    results = _by_setting({"min_length": 8}, "nist")
    assert all(result.passed for result in results.values())


def test_nist_profile_requires_eight_characters():
    assert _by_setting({"min_length": 7}, "nist")["min_length"].passed is False


def test_cis_profile_requires_fourteen_and_a_long_history():
    policy = {
        "min_length": 14, "require_upper": True, "require_lower": True,
        "require_digit": True, "require_symbol": True,
        "max_age_days": 365, "reuse_limit": 24,
    }
    assert all(result.passed for result in evaluate_policy(policy, "cis"))
    weak = _by_setting(dict(policy, min_length=12, reuse_limit=5), "cis")
    assert weak["min_length"].passed is False
    assert weak["reuse_limit"].passed is False


def test_cis_profile_rejects_a_zero_maximum_age():
    assert _by_setting({"min_length": 14, "max_age_days": 0}, "cis")["max_age_days"].passed is False


def test_pci_profile_requires_twelve_and_composition():
    policy = {
        "min_length": 12, "require_upper": True, "require_lower": True,
        "require_digit": True, "require_symbol": True,
        "max_age_days": 90, "reuse_limit": 4,
    }
    assert all(result.passed for result in evaluate_policy(policy, "pci"))
    assert _by_setting(dict(policy, require_symbol=False), "pci")["require_symbol"].passed is False
