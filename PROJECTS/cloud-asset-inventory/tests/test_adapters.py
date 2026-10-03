"""Each export shape is detected from structure and normalised."""
from src.inventory import (
    AWS_CONFIG,
    AZURE_RESOURCE_GRAPH,
    GENERIC,
    GCP_ASSET_INVENTORY,
    adapt_aws_config,
    adapt_azure_resource_graph,
    adapt_gcp_assets,
    adapt_generic,
    detect_format,
    parse_document,
)


def test_aws_config_shape_is_detected_and_normalised():
    data = {"resourceIdentifiers": [
        {"resourceType": "AWS::EC2::Instance", "resourceId": "i-1",
         "resourceName": "web", "awsRegion": "eu-west-2",
         "tags": {"Owner": "team"},
         "configuration": {"public": True, "encrypted": False}},
    ]}
    assert detect_format(data) == AWS_CONFIG
    assets, skipped = adapt_aws_config(data, "aws.json")
    assert skipped == 0
    asset = assets[0]
    assert asset.provider == "AWS"
    assert asset.resource_type == "AWS::EC2::Instance"
    assert asset.identifier == "i-1"
    assert asset.name == "web"
    assert asset.region == "eu-west-2"
    assert asset.tags == {"Owner": "team"}
    assert asset.public is True
    assert asset.encrypted is False


def test_aws_config_accepts_alternate_list_keys():
    data = {"Results": [
        {"resourceType": "AWS::S3::Bucket", "resourceId": "b-1"},
    ]}
    assert detect_format(data) == AWS_CONFIG
    assets, _ = adapt_aws_config(data, "aws.json")
    assert assets[0].identifier == "b-1"
    assert assets[0].name == "b-1"


def test_azure_resource_graph_shape_is_detected_and_normalised():
    data = {"value": [
        {"id": "/subscriptions/x/resourceGroups/lab/providers/Microsoft.Storage/storageAccounts/s1",
         "name": "s1", "type": "microsoft.storage/storageaccounts",
         "location": "eastus", "tags": {"Owner": "student"},
         "properties": {"publicNetworkAccess": "Enabled", "encrypted": False}},
    ]}
    assert detect_format(data) == AZURE_RESOURCE_GRAPH
    assets, skipped = adapt_azure_resource_graph(data, "azure.json")
    assert skipped == 0
    asset = assets[0]
    assert asset.provider == "Azure"
    assert asset.resource_type == "microsoft.storage/storageaccounts"
    assert asset.name == "s1"
    assert asset.region == "eastus"
    assert asset.public is True
    assert asset.encrypted is False


def test_azure_encryption_block_counts_as_encrypted():
    data = {"value": [
        {"id": "/x/y", "name": "s2", "type": "microsoft.storage/storageaccounts",
         "properties": {"encryption": {"services": {"blob": {"enabled": True}}}}},
    ]}
    assets, _ = adapt_azure_resource_graph(data, "azure.json")
    assert assets[0].encrypted is True
    assert assets[0].public is None


def test_gcp_asset_inventory_shape_is_detected_and_normalised():
    data = {"assets": [
        {"name": "//storage.googleapis.com/bucket-a",
         "assetType": "storage.googleapis.com/Bucket",
         "resource": {"location": "europe-west1", "labels": {"owner": "student"}},
         "iamPolicy": {"bindings": [
             {"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}},
    ]}
    assert detect_format(data) == GCP_ASSET_INVENTORY
    assets, skipped = adapt_gcp_assets(data, "gcp.json")
    assert skipped == 0
    asset = assets[0]
    assert asset.provider == "GCP"
    assert asset.resource_type == "storage.googleapis.com/Bucket"
    assert asset.name == "bucket-a"
    assert asset.identifier == "//storage.googleapis.com/bucket-a"
    assert asset.region == "europe-west1"
    assert asset.tags == {"owner": "student"}
    assert asset.public is True


def test_generic_shape_is_detected_and_normalised():
    data = {"assets": [
        {"provider": "AWS", "type": "EC2", "name": "web",
         "region": "eu-west-2", "tags": {"Owner": "o"}, "public": True},
    ]}
    assert detect_format(data) == GENERIC
    assets, _ = adapt_generic(data, "generic.json")
    assert assets[0].provider == "AWS"
    assert assets[0].identifier == "web"
    assert assets[0].public is True
    assert assets[0].encrypted is None


def test_unrecognised_document_is_rejected():
    try:
        detect_format({"something": "else"})
    except ValueError as exc:
        assert "Unrecognised export format" in str(exc)
    else:
        raise AssertionError("expected a ValueError")


def test_non_object_records_are_counted_as_skipped():
    data = {"resourceIdentifiers": [
        {"resourceType": "AWS::VPC", "resourceId": "vpc-1"},
        "not a record",
        42,
    ]}
    assets, skipped = adapt_aws_config(data, "aws.json")
    assert len(assets) == 1
    assert skipped == 2


def test_record_without_an_identifier_is_skipped():
    data = {"value": [{"type": "microsoft.compute/virtualmachines"}]}
    assets, skipped = adapt_azure_resource_graph(data, "azure.json")
    assert assets == []
    assert skipped == 1


def test_parse_document_reports_the_detected_format():
    fmt, assets, skipped = parse_document(
        {"assets": [{"assetType": "x", "name": "//a/b"}]}, "gcp.json"
    )
    assert fmt == GCP_ASSET_INVENTORY
    assert len(assets) == 1
    assert skipped == 0
