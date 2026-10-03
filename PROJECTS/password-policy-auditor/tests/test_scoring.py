"""Compliance scoring, the failing-settings list, and the exit code."""
import json

from src.audit import compliance_score, evaluate_policy, main


def test_a_fully_met_policy_scores_one_hundred():
    policy = {
        "min_length": 12, "require_upper": True, "require_lower": True,
        "require_digit": True, "require_symbol": True,
        "max_age_days": 90, "reuse_limit": 5,
    }
    assert compliance_score(evaluate_policy(policy, "baseline")) == 100


def test_score_is_a_percentage_of_settings_met():
    # The baseline-style policy meets only min_length under NIST: 1 of 6.
    policy = {
        "min_length": 12, "require_upper": True, "require_lower": True,
        "require_digit": True, "require_symbol": True,
        "max_age_days": 90, "reuse_limit": 5,
    }
    assert compliance_score(evaluate_policy(policy, "nist")) == round(100 * 1 / 6)


def test_failing_settings_are_listed_and_the_exit_code_is_nonzero(tmp_path, capsys):
    path = tmp_path / "policy.conf"
    path.write_text(
        "min_length=12\nrequire_upper=true\nrequire_lower=true\n"
        "require_digit=true\nrequire_symbol=true\nmax_age_days=90\nreuse_limit=5\n"
    )
    code = main([str(path), "--profile", "nist"])
    out = capsys.readouterr().out
    assert code == 1
    assert "Compliance: 17%" in out
    assert (
        "Failing settings: require_upper, require_lower, require_digit, "
        "require_symbol, max_age_days"
    ) in out


def test_a_passing_policy_exits_zero(tmp_path):
    path = tmp_path / "policy.conf"
    path.write_text(
        "min_length=14\nrequire_upper=true\nrequire_lower=true\n"
        "require_digit=true\nrequire_symbol=true\nmax_age_days=365\nreuse_limit=24\n"
    )
    assert main([str(path), "--profile", "cis"]) == 0


def test_json_policy_report_carries_the_score_and_failing_list(tmp_path, capsys):
    path = tmp_path / "policy.conf"
    path.write_text("min_length=12\nrequire_upper=true\n")
    code = main([str(path), "--profile", "nist", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 1
    assert data["mode"] == "policy"
    assert data["score"] == 83
    assert data["passed"] is False
    assert "require_upper" in data["failing"]
