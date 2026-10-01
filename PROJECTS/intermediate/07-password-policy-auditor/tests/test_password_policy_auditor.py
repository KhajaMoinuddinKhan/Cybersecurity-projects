from src.audit import audit_policy

def test_good_policy_passes_baseline():
    checks=audit_policy({
        "min_length":14,"require_upper":True,"require_lower":True,
        "require_digit":True,"require_symbol":True,"max_age_days":60,"reuse_limit":8
    })
    assert all(check.passed for check in checks)

def test_weak_password_reuse_history_requires_review():
    checks=audit_policy({
        "min_length":14,"require_upper":True,"require_lower":True,
        "require_digit":True,"require_symbol":True,"max_age_days":60,"reuse_limit":3
    })
    reuse_check=next(check for check in checks if check.setting=="reuse_limit")
    assert reuse_check.passed is False

def test_zero_max_age_requires_review():
    checks=audit_policy({
        "min_length":14,"require_upper":True,"require_lower":True,
        "require_digit":True,"require_symbol":True,"max_age_days":0,"reuse_limit":8
    })
    age_check=next(check for check in checks if check.setting=="max_age_days")
    assert age_check.passed is False


def test_misspelled_setting_is_reported(tmp_path):
    import pytest
    from src.audit import parse_policy
    path = tmp_path / "policy.conf"
    path.write_text("min_lenght=12")
    with pytest.raises(ValueError, match="unknown setting"):
        parse_policy(path)
