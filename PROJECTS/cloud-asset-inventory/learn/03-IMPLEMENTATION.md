# Implementation

- `REQUIRED_TAGS` defines the Owner and Environment metadata expected by the project.
- Public assets produce a medium-severity review item.
- Missing or malformed tags produce low-severity metadata findings.
- Assets without a region produce a separate low-severity finding.
- Provider, type, and name values are printed for each inventory record.

## Inputs and failure handling

The file must contain an object with an `assets` list. Each asset is an object that can include `provider`, `type`, `name`, `public`, `region`, and `tags`. Use a JSON boolean for `public` and an object for tags. The bundled file contains synthetic training data; an actual export must be mapped into this schema before use.

Check that the top-level key is exactly `assets`, and that the tag names match `Owner` and `Environment`. An empty assets list is valid and reports zero resources. Invalid JSON or a non-object asset stops loading with an error.

[Back to the project guide](../README.md)
