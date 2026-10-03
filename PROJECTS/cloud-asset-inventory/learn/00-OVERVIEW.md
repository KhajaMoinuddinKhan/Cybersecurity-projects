# Overview

Cloud Asset Inventory reads JSON exports of cloud resources and turns them into a short review list. It accepts four document shapes — an AWS Config resource list, an Azure Resource Graph `value` array, a GCP asset inventory `assets` array, and the tool's own generic `assets` shape — detects which one a file is from its structure, and normalises every record into a single asset with a provider, a resource type, an identifier, a name, a region, tags, a public-exposure flag and an encryption flag.

It then prints the inventory as a table, counts the assets by provider and by resource type, and reports findings: publicly exposed assets, assets missing an Owner or Environment tag, assets with no tags at all, assets with no recorded region, storage the export records as unencrypted, and values that were present but in the wrong shape.

## A useful first exercise

Run the bundled fixtures and note which resources lack ownership, environment, or region information, and which one is marked public:

```console
python -m src.inventory sample_exports/ sample_assets.json
```

Then open one of the sample exports, fix a field, and run it again to watch the finding disappear. Leave the public flag alone unless the underlying exposure actually changed; editing inventory metadata does not change cloud configuration.

## What it is not

The program does not authenticate to a cloud provider or discover resources. It reviews only the exports you give it, which can be incomplete or out of date. A public flag does not describe actual firewall reachability, and a populated tag can still contain incorrect information. A missing exposure or encryption field is reported as unknown, never as safe. Global resources may legitimately need a different region policy.

[Back to the project guide](../README.md)
