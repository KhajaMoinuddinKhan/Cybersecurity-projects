"""Password list checks: every failure reason, the context check and the CLI."""
import json

from src.audit import (
    PasswordRules,
    check_password,
    effective_password_rules,
    main,
)

STRICT = PasswordRules(
    min_length=12,
    require_upper=True,
    require_lower=True,
    require_digit=True,
    require_symbol=True,
)
PERMISSIVE = PasswordRules(
    min_length=1,
    require_upper=False,
    require_lower=False,
    require_digit=False,
    require_symbol=False,
)


def test_too_short_is_reported_with_both_numbers():
    assert check_password("Ab1!Ab1!", STRICT) == ["too short (8 < 12)"]


def test_missing_required_classes_are_reported():
    reasons = check_password("lowercaseonly", STRICT)
    assert "missing required uppercase" in reasons
    assert "missing required digit" in reasons
    assert "missing required symbol" in reasons


def test_a_common_password_is_reported_case_insensitively():
    assert check_password("PASSWORD", PERMISSIVE) == ["is a known common password"]
    assert check_password("letmein", PERMISSIVE) == ["is a known common password"]


def test_a_repeated_character_run_is_reported():
    assert check_password("zzzzzzzz", PERMISSIVE) == ["contains a repeated character run"]


def test_a_sequential_string_is_reported():
    assert "contains a sequential string" in check_password("abcdefgh", PERMISSIVE)
    assert "contains a sequential string" in check_password("98765432", PERMISSIVE)


def test_a_keyboard_run_is_reported():
    assert check_password("qwertyui", PERMISSIVE) == ["contains a keyboard run"]


def test_a_context_term_inside_a_password_is_reported():
    assert check_password("acme2024", PERMISSIVE, ["acme"]) == ["contains context term 'acme'"]


def test_the_context_check_ignores_case():
    reasons = check_password("AcmeCorp", PERMISSIVE, ["ACME"])
    assert any(reason.startswith("contains context term") for reason in reasons)


def test_a_clean_password_passes_every_check():
    assert check_password("Tr0ub4dor&3xY", STRICT) == []


def test_effective_rules_take_the_policy_over_the_profile():
    rules = effective_password_rules({"min_length": 16, "require_upper": True}, "nist")
    assert rules.min_length == 16
    assert rules.require_upper is True
    # A setting the file does not mention keeps the profile default.
    assert rules.require_digit is False


def test_password_mode_reports_each_reason(tmp_path, capsys):
    policy = tmp_path / "policy.conf"
    policy.write_text(
        "min_length=12\nrequire_upper=true\nrequire_lower=true\n"
        "require_digit=true\nrequire_symbol=true\n"
    )
    words = tmp_path / "words.txt"
    words.write_text("Ab1!Ab1!\nqwertyuiZX1!a\nAcme-Corp-2024\nTr0ub4dor&3xY\n")
    code = main([str(policy), "--passwords", str(words), "--context", "acme"])
    out = capsys.readouterr().out
    assert code == 1
    assert "too short" in out
    assert "contains a keyboard run" in out
    assert "contains context term 'acme'" in out
    assert "1 of 4 candidate passwords passed" in out


def test_password_mode_json_lists_failures(tmp_path, capsys):
    words = tmp_path / "words.txt"
    words.write_text("password\nTr0ub4dor&3xY\n")
    code = main(["--passwords", str(words), "--profile", "nist", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 1
    assert data["mode"] == "passwords"
    assert data["total"] == 2
    assert data["failed"] == 1
    assert data["passwords"][0]["reasons"] == ["is a known common password"]
