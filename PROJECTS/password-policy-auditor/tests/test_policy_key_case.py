"""Regression: the README documents policy keys as case-insensitive."""
from src.audit import audit_policy, parse_policy


def test_policy_keys_are_case_insensitive(tmp_path):
    path = tmp_path / "policy.conf"
    path.write_text("MIN_LENGTH=14\nRequire_Upper=true\n", encoding="utf-8")
    assert parse_policy(path) == {"min_length": 14, "require_upper": True}


def test_mixed_case_keys_audit_without_an_unknown_setting_error(tmp_path):
    path = tmp_path / "policy.conf"
    path.write_text("Min_Length=14\nREQUIRE_UPPER=TRUE\n", encoding="utf-8")
    checks = {check.setting: check for check in audit_policy(parse_policy(path))}
    assert checks["min_length"].passed is True
    assert checks["require_upper"].passed is True
