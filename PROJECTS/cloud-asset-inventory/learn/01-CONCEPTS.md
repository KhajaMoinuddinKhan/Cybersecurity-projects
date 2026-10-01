# Concepts

- Asset inventory records what resources exist and gives analysts a consistent review point.
- Public exposure is useful context for prioritizing cloud resources.
- Owner and Environment tags help connect assets to responsibility and purpose.
- Region data supports location, residency, and incident-response context.
- Input validation prevents malformed asset structures from being treated as valid inventory.

## Interpreting the evidence

The command prints the inventory first, then findings labeled with the asset name. Public assets receive a medium-priority review item. Missing Owner or Environment tags, malformed tag structures, and missing regions receive low-priority findings. A resource can produce more than one finding.

The program does not authenticate to a cloud provider or discover resources. It reviews only the data you give it, which can be incomplete or out of date. A public flag does not describe actual firewall reachability, and a populated tag can still contain incorrect information. Global resources may legitimately need a different region policy.

[Back to the project guide](../README.md)
