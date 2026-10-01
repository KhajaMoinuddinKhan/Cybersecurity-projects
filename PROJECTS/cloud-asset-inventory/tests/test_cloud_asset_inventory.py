from src.inventory import load_assets, review_assets

def test_public_asset_and_missing_metadata_are_flagged():
    findings=review_assets([{"type":"EC2","name":"demo","public":True,"tags":{},"region":"eu-west-2"}])
    assert any(severity=="MEDIUM" for severity,_,_ in findings)
    assert any("Owner" in message for _,_,message in findings)

def test_malformed_tags_are_reported_instead_of_crashing():
    findings=review_assets([{"type":"Storage","name":"demo","public":False,"tags":[],"region":"eu-west-2"}])
    assert any("Tags are not stored as a JSON object" in message for _,_,message in findings)


def test_invalid_exposure_and_blank_tags_are_not_silently_accepted():
    findings = review_assets([{"name": "asset", "public": "true", "tags": {"Owner": "   ", "Environment": 42}, "region": "lab"}])
    messages = " ".join(message for _, _, message in findings)
    assert "JSON boolean" in messages
    assert "Owner" in messages and "Environment" in messages


def test_utf8_bom_file_is_accepted(tmp_path):
    path = tmp_path / "assets.json"
    path.write_text('{"assets": []}', encoding="utf-8-sig")
    assert load_assets(path) == []


def test_blank_region_is_treated_as_missing():
    findings = review_assets([
        {"name": "a", "type": "EC2", "public": False,
         "tags": {"Owner": "o", "Environment": "e"}, "region": "   "}
    ])
    assert any("Region is not recorded" in message for _, _, message in findings)


def test_recorded_region_is_not_flagged():
    findings = review_assets([
        {"name": "a", "type": "EC2", "public": False,
         "tags": {"Owner": "o", "Environment": "e"}, "region": "eu-west-2"}
    ])
    assert not any("Region" in message for _, _, message in findings)


def test_numeric_region_is_reported_as_the_wrong_type():
    findings = review_assets([
        {"name": "a", "type": "EC2", "public": False,
         "tags": {"Owner": "o", "Environment": "e"}, "region": 12345}
    ])
    messages = " ".join(message for _, _, message in findings)
    assert "Region must be recorded as text" in messages
    assert "Region is not recorded" not in messages
