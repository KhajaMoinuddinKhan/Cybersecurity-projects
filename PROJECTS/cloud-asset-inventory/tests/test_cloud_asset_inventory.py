"""Normalisation, loading and the bundled sample exports."""
from pathlib import Path

from src.inventory import GENERIC, build_findings, load_export

PROJECT_DIR = Path(__file__).resolve().parents[1]


def test_generic_sample_loads_three_assets():
    fmt, assets, skipped = load_export(PROJECT_DIR / "sample_assets.json")
    assert fmt == GENERIC
    assert skipped == 0
    assert [asset.name for asset in assets] == ["web-server-01", "student-storage", "lab-network"]


def test_public_asset_and_missing_metadata_are_flagged():
    findings = build_findings(
        load_export(PROJECT_DIR / "sample_assets.json")[1]
    )
    assert any(finding.severity == "MEDIUM" for finding in findings)
    assert any("Owner" in finding.message for finding in findings)


def test_malformed_tags_are_reported_instead_of_crashing():
    data = {"assets": [
        {"type": "Storage", "name": "demo", "public": False, "tags": [], "region": "eu-west-2"}
    ]}
    findings = build_findings(load_export_dict(data))
    assert any("Tags are not stored as a JSON object" in finding.message for finding in findings)


def test_invalid_exposure_and_blank_tags_are_not_silently_accepted():
    data = {"assets": [
        {"name": "asset", "public": "true", "tags": {"Owner": "   ", "Environment": 42}, "region": "lab"}
    ]}
    messages = " ".join(finding.message for finding in build_findings(load_export_dict(data)))
    assert "JSON boolean" in messages
    assert "Owner" in messages and "Environment" in messages


def test_utf8_bom_file_is_accepted(tmp_path):
    path = tmp_path / "assets.json"
    path.write_text('{"assets": []}', encoding="utf-8-sig")
    fmt, assets, skipped = load_export(path)
    assert fmt == GENERIC
    assert assets == []


def test_blank_region_is_treated_as_missing():
    data = {"assets": [
        {"name": "a", "type": "EC2", "public": False,
         "tags": {"Owner": "o", "Environment": "e"}, "region": "   "}
    ]}
    findings = build_findings(load_export_dict(data))
    assert any("Region is not recorded" in finding.message for finding in findings)


def test_recorded_region_is_not_flagged():
    data = {"assets": [
        {"name": "a", "type": "EC2", "public": False,
         "tags": {"Owner": "o", "Environment": "e"}, "region": "eu-west-2"}
    ]}
    findings = build_findings(load_export_dict(data))
    assert not any("Region" in finding.message for finding in findings)


def test_numeric_region_is_reported_as_the_wrong_type():
    data = {"assets": [
        {"name": "a", "type": "EC2", "public": False,
         "tags": {"Owner": "o", "Environment": "e"}, "region": 12345}
    ]}
    messages = " ".join(finding.message for finding in build_findings(load_export_dict(data)))
    assert "Region must be recorded as text" in messages
    assert "Region is not recorded" not in messages


def load_export_dict(data):
    """Normalise an in-memory document the way a file would be loaded."""

    from src.inventory import parse_document

    return parse_document(data, "inline.json")[1]
