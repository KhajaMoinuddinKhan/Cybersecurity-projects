# Cloud Asset Inventory

Cloud inventories are easy to produce and easy to ignore. This tool takes a JSON export of your resources and turns it into a short list of things that deserve a second look: an asset marked public, a resource nobody owns, a missing environment tag, a region that was never recorded.

It reviews the file you give it. It does not authenticate to a provider, call an API, or discover anything you did not export yourself.

## Running it

Standard library only:

```console
python -m src.inventory sample_assets.json
```

The bundled fixture shows the shape of the output:

```
Assets found: 3
- AWS | EC2 | web-server-01
- Azure | Storage | student-storage
- AWS | VPC | lab-network

Basic findings:
[MEDIUM] web-server-01: EC2 is marked public.
[LOW] web-server-01: Missing metadata: Environment
[LOW] web-server-01: Region is not recorded.
[LOW] student-storage: Missing metadata: Owner, Environment
[LOW] student-storage: Region is not recorded.
[LOW] lab-network: Missing metadata: Environment
[LOW] lab-network: Region is not recorded.
```

The inventory is printed first so you can see what was read, then the findings, each naming the asset it belongs to.

## The file format

An object with an `assets` list. Each asset can carry `provider`, `type`, `name`, `public`, `region` and `tags`. `public` must be a JSON boolean; anything else gets a finding rather than being coerced into true or false. `tags` must be an object, and the required tags (`Owner` and `Environment`) must be non-empty text. A region that is missing, blank, or not text at all is reported as a problem, because a number where a region belongs is a data error, not a region.

A file saved with a UTF-8 byte order mark loads normally.

## Reading the results

`public: true` produces a review item, not a verdict. "Public" in an inventory export can mean a deliberately internet-facing load balancer or an S3 bucket that should never have been opened, and the file alone cannot tell you which. Missing ownership and environment tags are the quiet findings: they are how a resource becomes nobody's problem, and they are usually the cheapest thing on this list to fix.

## Tests

```console
python -m pytest -q tests
```

Tests cover public assets, missing and malformed metadata, non-boolean exposure flags, blank and non-text regions, byte-order-mark files, and the bundled fixture.
