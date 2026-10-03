"""Every configured finding, with its severity and explanation."""
from src.inventory import Asset, build_findings


def asset(**overrides):
    base = dict(
        provider="AWS", resource_type="AWS::EC2::Instance", identifier="i-1",
        name="web", region="eu-west-2", tags={"Owner": "o", "Environment": "e"},
        public=False, encrypted=None, source="x.json",
    )
    base.update(overrides)
    return Asset(**base)


def categories(assets):
    return {finding.category for finding in build_findings(assets)}


def test_publicly_exposed_asset_is_a_medium_finding():
    findings = build_findings([asset(public=True)])
    exposed = [f for f in findings if f.category == "PUBLIC_EXPOSURE"]
    assert exposed and exposed[0].severity == "MEDIUM"
    assert "publicly exposed" in exposed[0].message


def test_missing_owner_or_environment_is_reported():
    findings = build_findings([asset(tags={"Owner": "o"})])
    missing = [f for f in findings if f.category == "MISSING_OWNER_ENV"]
    assert missing and "Environment" in missing[0].message
    assert missing[0].severity == "LOW"


def test_required_tags_are_matched_case_insensitively():
    findings = build_findings([asset(tags={"owner": "o", "environment": "e"})])
    assert "MISSING_OWNER_ENV" not in {f.category for f in findings}


def test_blank_tag_value_does_not_count_as_present():
    findings = build_findings([asset(tags={"Owner": "   ", "Environment": "e"})])
    assert "MISSING_OWNER_ENV" in {f.category for f in findings}


def test_asset_with_no_tags_is_reported():
    findings = build_findings([asset(tags={})])
    assert "MISSING_TAGS" in {f.category for f in findings}


def test_missing_region_is_reported():
    findings = build_findings([asset(region=None)])
    assert "MISSING_REGION" in {f.category for f in findings}


def test_unencrypted_storage_is_reported():
    findings = build_findings([
        asset(resource_type="AWS::S3::Bucket", encrypted=False)
    ])
    unencrypted = [f for f in findings if f.category == "UNENCRYPTED_STORAGE"]
    assert unencrypted and unencrypted[0].severity == "MEDIUM"


def test_unknown_encryption_state_is_not_reported():
    findings = build_findings([
        asset(resource_type="AWS::S3::Bucket", encrypted=None)
    ])
    assert "UNENCRYPTED_STORAGE" not in {f.category for f in findings}


def test_unencrypted_non_storage_is_not_reported():
    findings = build_findings([
        asset(resource_type="AWS::EC2::Instance", encrypted=False)
    ])
    assert "UNENCRYPTED_STORAGE" not in {f.category for f in findings}


def test_malformed_values_become_data_quality_findings():
    findings = build_findings([
        asset(problems=(
            "Public exposure must be recorded as a JSON boolean.",
            "Region must be recorded as text.",
        ))
    ])
    quality = [f for f in findings if f.category == "DATA_QUALITY"]
    assert len(quality) == 2
    assert all(f.severity == "LOW" for f in quality)


def test_a_clean_asset_produces_no_findings():
    assert build_findings([asset()]) == []
