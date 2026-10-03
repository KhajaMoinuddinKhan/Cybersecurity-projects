# Cloud Asset Inventory

Cloud inventories are easy to produce and easy to ignore. This tool reads JSON exports of your resources — an AWS Config resource list, an Azure Resource Graph `value` array, a GCP asset inventory `assets` array, or the tool's own generic shape — normalises every record into one asset, and turns the result into a short list of things that deserve a second look: an asset marked public, a resource nobody owns, a missing environment tag, a region that was never recorded, storage the export says is unencrypted.

It reviews the files you give it. It does not authenticate to a provider, call an API, or discover anything you did not export yourself. Every "provider" it knows about is a document shape it can parse, not a connection it can open.

## Running it

Standard library only:

```console
python -m src.inventory sample_exports/aws_config_resources.json sample_exports/gcp_assets.json
```

You can pass several files, a directory of exports (every `.json` file directly inside it), or both in one run:

```console
python -m src.inventory sample_exports/
python -m src.inventory sample_exports/ sample_assets.json
```

The bundled fixtures show the shape of the output:

```
Per-file report:
  sample_exports\aws_config_resources.json: parsed 3 asset(s) as aws-config
  sample_exports\gcp_assets.json: parsed 2 asset(s) as gcp-asset-inventory

Assets found: 5
PROVIDER  TYPE                             NAME                   REGION
--------  -------------------------------  ---------------------  --------------
AWS       AWS::EC2::Instance               web-server-01          eu-west-2
AWS       AWS::S3::Bucket                  student-artifacts      eu-west-2
AWS       AWS::VPC                         lab-network            -
GCP       compute.googleapis.com/Instance  gce-lab                europe-west1-b
GCP       storage.googleapis.com/Bucket    student-public-bucket  europe-west1

Counts by provider:
  AWS: 3
  GCP: 2
Counts by type:
  AWS::EC2::Instance: 1
  AWS::S3::Bucket: 1
  AWS::VPC: 1
  compute.googleapis.com/Instance: 1
  storage.googleapis.com/Bucket: 1

Findings: 7
[MEDIUM] PUBLIC_EXPOSURE web-server-01: AWS::EC2::Instance is marked publicly exposed.
[LOW] MISSING_OWNER_ENV student-artifacts: Missing metadata: Environment
[MEDIUM] UNENCRYPTED_STORAGE student-artifacts: AWS::S3::Bucket records encryption as disabled.
[LOW] MISSING_REGION lab-network: Region is not recorded.
[MEDIUM] PUBLIC_EXPOSURE student-public-bucket: storage.googleapis.com/Bucket is marked publicly exposed.
[LOW] MISSING_TAGS student-public-bucket: No tags are recorded.
[LOW] MISSING_OWNER_ENV student-public-bucket: Missing metadata: Owner, Environment
```

The per-file report says what each input contributed; then the inventory table; then counts grouped by provider and by type; then the findings, each naming the asset it belongs to.

## Export formats

The format is auto-detected from the document structure, so you do not name it. Four shapes are recognised:

- **AWS Config resource list** — a top-level list under `resourceIdentifiers`, `results`, `Results`, `configurationItems` or `ConfigurationItems`, whose records carry a `resourceType` and a `resourceId`. Provider `AWS`. Region from `awsRegion`, tags from `tags`. Exposure and encryption come from a boolean `public`/`encrypted` on the record, or from the same keys inside a `configuration` block.
- **Azure Resource Graph** — a top-level `value` array of records carrying an `id` and a `type`. Provider `Azure`. Region from `location`, tags from `tags`. Exposure from `publicNetworkAccess` / `publicAccess` (`"Enabled"`/`"Disabled"`), `allowBlobPublicAccess`, or an explicit boolean. Encryption from an `encryption` block, or an explicit boolean.
- **GCP asset inventory** — a top-level `assets` array whose records carry an `assetType` and a full resource `name`. Provider `GCP`. Region from `resource.location`, tags from `resource.labels` (or `tags`). Exposure is `true` when an `iamPolicy` binding lists `allUsers` or `allAuthenticatedUsers`, or when an explicit boolean is set. Encryption from a `resource.data.encryption` block, or an explicit boolean.
- **Generic** — a top-level `assets` array of the tool's own records: `provider`, `type`, `name`, `region`, `tags`, `public`, `encrypted`. This is the shape in `sample_assets.json`.

Every record is normalised to the same fields: `provider`, `resource_type`, `identifier`, `name`, `region`, `tags`, `public`, `encrypted`, and the `source` file it came from. `public` and `encrypted` are `true`, `false`, or `null` when the export does not record that state — a null means unknown, not safe.

## Findings

Each finding has a severity, a category, the asset it belongs to, and an explanation:

- `PUBLIC_EXPOSURE` (MEDIUM) — the asset is marked publicly exposed.
- `UNENCRYPTED_STORAGE` (MEDIUM) — a storage-like resource (its type contains `storage`, `bucket`, `blob`, `disk`, `volume`, `filesystem` or `filestore`) records encryption as disabled. It is not raised when the export does not record encryption at all.
- `MISSING_TAGS` (LOW) — the resource has no tags.
- `MISSING_OWNER_ENV` (LOW) — the resource is missing an `Owner` or `Environment` tag. Tag names are matched case-insensitively, so GCP's lower-case `owner`/`environment` labels count; a tag whose value is blank or not text does not count.
- `MISSING_REGION` (LOW) — no region is recorded.
- `DATA_QUALITY` (LOW) — a value was present but in the wrong shape: exposure or encryption that is not a JSON boolean, tags that are not an object, or a region that is not text.

A resource can produce more than one finding. A resource with no tags at all triggers both `MISSING_TAGS` and `MISSING_OWNER_ENV`.

## Exports

Write the normalised inventory and the findings to JSON or CSV:

```console
python -m src.inventory sample_exports/ \
    --inventory-json inventory.json --inventory-csv inventory.csv \
    --findings-json findings.json  --findings-csv findings.csv
```

The inventory CSV carries `provider, resource_type, identifier, name, region, public, encrypted, source, tags`, with the tags object stored as a JSON string in one column. The findings CSV carries `severity, category, asset, provider, message`.

## JSON mode

`--json` prints the whole report as one JSON document instead of the table — the per-file report, every normalised asset, the grouped counts, and the findings:

```console
python -m src.inventory sample_exports/ --json
```

```json
{
  "files": [{"path": "sample_exports\\gcp_assets.json", "format": "gcp-asset-inventory", "assets": 2, "skipped": 0, "error": null}],
  "assets": [{"provider": "GCP", "resource_type": "storage.googleapis.com/Bucket", "identifier": "//storage.googleapis.com/student-public-bucket", "name": "student-public-bucket", "region": "europe-west1", "tags": {}, "public": true, "encrypted": true, "source": "gcp_assets.json"}],
  "counts": {"by_provider": {"GCP": 2}, "by_type": {"compute.googleapis.com/Instance": 1, "storage.googleapis.com/Bucket": 1}},
  "findings": [{"severity": "MEDIUM", "category": "PUBLIC_EXPOSURE", "asset": "student-public-bucket", "provider": "GCP", "message": "storage.googleapis.com/Bucket is marked publicly exposed."}]
}
```

(Abridged for readability; a real run lists every asset and finding.) Export messages go to stderr in `--json` mode so stdout stays a single valid document.

## What a run does not do

- It reads exports. It never authenticates to AWS, Azure or GCP, never calls their APIs, and never discovers a resource you did not export. If an export is incomplete or stale, so is the inventory.
- A file that cannot be read, is not valid JSON, or does not match a known shape is reported in the per-file report and skipped; the rest of the run continues. A directory with no `.json` files and a path that does not exist are reported the same way.
- `public` and `encrypted` are only as good as the field the export provides. A missing flag is reported as `null` (unknown) and never guessed. A `public: true` is a review item, not a verdict: "public" in an export can mean a deliberately internet-facing load balancer or a bucket that should never have been opened, and the file alone cannot tell you which.
- The GCP public check is a literal member test for `allUsers`/`allAuthenticatedUsers`; it does not evaluate conditions, roles, or inherited policy.
- Findings are review priorities, not risk scores. Severity reflects how cheap the item is to look at, not a modelled likelihood.
- The tool does not deduplicate across files: the same resource present in two exports appears twice.
- Global resources may legitimately carry no region, and the storage markers are a heuristic over the resource-type string, not a catalogue of every storage service.

## Tests

```console
python -m pytest -q tests
```

Tests cover each adapter and format detection, normalisation (region, tag and boolean coercion), the grouped counts, every finding category, per-file reporting for good and broken inputs, the JSON and CSV exports, JSON mode, byte-order-mark files, and deeply nested JSON.
