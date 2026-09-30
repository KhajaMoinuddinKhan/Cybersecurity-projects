from src.inventory import review_assets

def test_public_asset_and_missing_metadata_are_flagged():
    findings=review_assets([{"type":"EC2","name":"demo","public":True,"tags":{},"region":"eu-west-2"}])
    assert any(severity=="MEDIUM" for severity,_,_ in findings)
    assert any("Owner" in message for _,_,message in findings)

def test_malformed_tags_are_reported_instead_of_crashing():
    findings=review_assets([{"type":"Storage","name":"demo","public":False,"tags":[],"region":"eu-west-2"}])
    assert any("Tags are not stored as a JSON object" in message for _,_,message in findings)
