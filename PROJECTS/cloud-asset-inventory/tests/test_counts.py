"""Assets are counted by provider and by resource type."""
from src.inventory import Asset, group_counts


def make(provider, resource_type):
    return Asset(
        provider=provider, resource_type=resource_type, identifier="id",
        name="name", region="r", tags={}, public=None, encrypted=None, source="x",
    )


def test_counts_group_by_provider_and_type():
    assets = [
        make("AWS", "AWS::EC2::Instance"),
        make("AWS", "AWS::S3::Bucket"),
        make("Azure", "microsoft.storage/storageaccounts"),
        make("GCP", "storage.googleapis.com/Bucket"),
    ]
    counts = group_counts(assets)
    assert counts["by_provider"] == {"AWS": 2, "Azure": 1, "GCP": 1}
    assert counts["by_type"]["AWS::S3::Bucket"] == 1
    assert counts["by_type"]["microsoft.storage/storageaccounts"] == 1


def test_counts_are_empty_for_no_assets():
    counts = group_counts([])
    assert counts == {"by_provider": {}, "by_type": {}}
