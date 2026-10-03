# Implementation

- `Asset` is the normalised record; `Finding`, `FileReport` and `Report` carry the review output.
- Four adapters — `adapt_aws_config`, `adapt_azure_resource_graph`, `adapt_gcp_assets`, `adapt_generic` — each return `(assets, skipped)`.
- `_coerce_region`, `_coerce_tags` and `_coerce_bool` turn raw fields into clean values and record a data-quality problem when a value is present but the wrong type.
- `build_findings` applies the rules and returns findings with a severity and a category.
- `group_counts` counts assets by provider and by resource type; `render_table` prints the stable table.

## Rules and severities

`PUBLIC_EXPOSURE` and `UNENCRYPTED_STORAGE` are MEDIUM; `MISSING_TAGS`, `MISSING_OWNER_ENV`, `MISSING_REGION` and `DATA_QUALITY` are LOW. `UNENCRYPTED_STORAGE` fires only for storage-like resource types (the type string contains `storage`, `bucket`, `blob`, `disk`, `volume`, `filesystem` or `filestore`) and only when the export records encryption as `false`; an unrecorded state (`null`) is left alone. `MISSING_REGION` is suppressed when the region was present but not text, because the data-quality finding already explains it.

## Inputs and failure handling

The field names each adapter reads are listed in the README's "Export formats" section. A record without the fields needed to identify it — no `resourceType`/`resourceId` for AWS, no `type`/`id` for Azure, no `assetType`/`name` for GCP — is counted as skipped rather than guessed at. Invalid JSON, a non-UTF-8 file, a deeply nested document, an unrecognised shape, a directory with no `.json` files and a missing path are all reported per file; none of them stop the run. An empty assets list is valid and reports zero resources.

The CSV export stores the tags object as a JSON string in a single column, because a tag set does not fit a flat table. `--json` writes one document and sends the export-confirmation messages to stderr so stdout stays parseable.

[Back to the project guide](../README.md)
