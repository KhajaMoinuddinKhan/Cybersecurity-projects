"""The grade is derived only from the checks the scanner actually performed."""
from __future__ import annotations

from src.scanner import grade_assessment

def base_assessment(**overrides):
    assessment = {
        "protocols": {
            "TLSv1.0": {"accepted": False, "deprecated": True, "probe_performed": True},
            "TLSv1.1": {"accepted": False, "deprecated": True, "probe_performed": True},
            "TLSv1.2": {"accepted": True, "deprecated": False, "probe_performed": True},
            "TLSv1.3": {"accepted": True, "deprecated": False, "probe_performed": True},
        },
        "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
        "offered_weak_ciphers": [
            {"family": family, "supported": False, "probe_performed": True}
            for family in ("RC4", "3DES", "DES", "NULL", "EXPORT", "anonymous", "MD5")
        ],
        "forward_secrecy": True,
        "certificate": {
            "expiry_status": "ok",
            "days_until_expiry": 200.0,
            "key_type": "RSA",
            "key_size": 2048,
            "weak_signature": False,
            "signature_algorithm": "RSA/SHA-256",
        },
        "self_signed": False,
        "chain_valid": True,
        "hostname_matches": True,
        "hsts": {"checked": True, "present": True, "max_age": 31536000},
    }
    assessment.update(overrides)
    return assessment

def test_clean_assessment_gets_an_a():
    result = grade_assessment(base_assessment())
    assert result["letter"] == "A"
    assert result["score"] == 100
    assert result["reasons"] == []

def test_deprecated_protocol_is_reported_and_deducted():
    assessment = base_assessment()
    assessment["protocols"]["TLSv1.0"] = {"accepted": True, "deprecated": True, "probe_performed": True}
    result = grade_assessment(assessment)
    assert result["score"] == 75
    assert any("TLSv1.0" in reason for reason in result["reasons"])

def test_weak_negotiated_cipher_is_deducted():
    result = grade_assessment(base_assessment(cipher="RC4-SHA"))
    assert result["score"] == 70
    assert any("weak" in reason for reason in result["reasons"])

def test_offered_weak_cipher_family_is_deducted():
    assessment = base_assessment()
    assessment["offered_weak_ciphers"][0] = {"family": "RC4", "supported": True, "probe_performed": True}
    result = grade_assessment(assessment)
    assert result["score"] == 90
    assert any("RC4" in reason for reason in result["reasons"])

def test_self_signed_is_not_double_counted_with_chain_failure():
    result = grade_assessment(base_assessment(self_signed=True, chain_valid=False))
    assert result["score"] == 70
    assert sum("self-signed" in reason for reason in result["reasons"]) == 1
    assert not any("did not validate" in reason for reason in result["reasons"])

def test_untrusted_chain_is_deducted_once():
    result = grade_assessment(base_assessment(chain_valid=False))
    assert result["score"] == 70

def test_expired_certificate_scores_low():
    assessment = base_assessment()
    assessment["certificate"] = dict(assessment["certificate"], expiry_status="expired", days_until_expiry=-5.0)
    result = grade_assessment(assessment)
    assert result["score"] == 60
    assert result["letter"] == "D"

def test_unperformed_checks_are_listed_not_deducted():
    assessment = base_assessment()
    assessment["protocols"]["TLSv1.0"] = {"accepted": False, "deprecated": True, "probe_performed": False}
    assessment["hsts"] = {"checked": False}
    result = grade_assessment(assessment)
    assert result["score"] == 100
    assert any("TLSv1.0" in note for note in result["not_checked"])
    assert any("HSTS" in note for note in result["not_checked"])

def test_short_hsts_max_age_is_deducted():
    result = grade_assessment(base_assessment(hsts={"checked": True, "present": True, "max_age": 300}))
    assert result["score"] == 95

def test_hostname_mismatch_is_deducted():
    result = grade_assessment(base_assessment(hostname_matches=False))
    assert result["score"] == 70
    assert any("hostname" in reason for reason in result["reasons"])

def test_missing_forward_secrecy_is_deducted():
    result = grade_assessment(base_assessment(forward_secrecy=False))
    assert result["score"] == 85
