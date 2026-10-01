"""Regression tests for policy-file encoding handling."""
from src.audit import audit_policy, parse_policy


def test_parse_policy_accepts_utf8_bom(tmp_path):
    path = tmp_path / "bom.conf"
    path.write_bytes("min_length=14\nrequire_upper=true\n".encode("utf-8-sig"))
    assert parse_policy(path) == {"min_length": 14, "require_upper": True}


def test_audits_bom_policy_without_unknown_setting_error(tmp_path):
    path = tmp_path / "bom.conf"
    path.write_bytes("min_length=14\n".encode("utf-8-sig"))
    checks = {c.setting: c for c in audit_policy(parse_policy(path))}
    assert checks["min_length"].passed is True
