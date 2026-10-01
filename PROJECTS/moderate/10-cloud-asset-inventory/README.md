# Cloud Asset Inventory

An inventory becomes more useful when each resource has enough context for someone to take responsibility for it. This project reads a JSON export, lists the assets, and flags public exposure or missing ownership, environment, and region information.

## Run it

Open a terminal in this project directory. Use Python 3.12 or 3.13; the repository's [setup guide](../../../README.md#get-started-in-vs-code) explains virtual environments and dependency installation.

```console
python -m src.inventory sample_assets.json
```

The file must contain an object with an `assets` list. Each asset is an object that can include `provider`, `type`, `name`, `public`, `region`, and `tags`. Use a JSON boolean for `public` and an object for tags. The bundled file contains synthetic training data; an actual export must be mapped into this schema before use.

## Read the result

The command prints the inventory first, then findings labeled with the asset name. Public assets receive a medium-priority review item. Missing Owner or Environment tags, malformed tag structures, and missing regions receive low-priority findings. A resource can produce more than one finding.

## How the code works

`load_assets()` checks the top-level structure and ensures every asset is an object. `review_assets()` applies the small configured rule set. Tag data that is not an object produces an explicit finding and is treated as missing metadata for the remaining checks, rather than crashing the entire review.

The [learning notes](learn/00-OVERVIEW.md) explain the concepts, implementation decisions, and tradeoffs in more detail.

## Try a small investigation

Run the bundled fixture and note which resources lack ownership, environment, or region information. Add those fields in a copy and compare the findings. Leave the public flag alone unless the underlying exposure actually changed; editing inventory metadata does not change cloud configuration.

## Troubleshooting and scope

Check that the top-level key is exactly `assets`, and that the tag names match `Owner` and `Environment`. An empty assets list is valid and reports zero resources. Invalid JSON or a non-object asset stops loading with an error.

The program does not authenticate to a cloud provider or discover resources. It reviews only the data you give it, which can be incomplete or out of date. A public flag does not describe actual firewall reachability, and a populated tag can still contain incorrect information. Global resources may legitimately need a different region policy.

## Tests

From this project directory, install pytest and run the tests:

```console
python -m pip install pytest
python -m pytest -q tests
```

Tests use controlled inputs and temporary files where needed. They verify the behavior of the configured checks; they do not establish that every real-world threat or configuration is covered.

## Output reference

![Cloud Asset Inventory](assets/cloud-asset-inventory-demo.jpg)

The command output depends on your input. Use the run instructions above to reproduce a report with your own data.
