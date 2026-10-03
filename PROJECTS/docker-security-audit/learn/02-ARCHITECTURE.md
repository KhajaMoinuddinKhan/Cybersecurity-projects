# Architecture

1. The command line accepts one or more saved Docker inspect JSON files, plus `--json` and `--fail-on`.
2. `load_json()` accepts a single inspect object or Docker's list form, for one container or several.
3. `audit_container()` runs a set of small check functions over the `HostConfig`, `Config`, `NetworkSettings` and `Mounts` sections, appending a `Finding` for each rule that fires.
4. A `Finding` holds a severity, evidence, an explanation and an optional control reference.
5. The command prints the report, or a JSON document, and sets the exit code from the highest severity present.

## Follow one run

The loader validates the JSON structure, and `audit_container()` reads the container's configuration through small helpers: `_object` and `_list` for shape-checked access, `bind_spec` for a bind string and its read-only flag, `sensitive_mount` for a sensitive host path, and `_image_tag` for the image reference. Findings are collected in a fixed order, so the same input always produces the same report.

Before printing anything, the command audits every container in every file, so an invalid entry fails cleanly instead of leaving a half-written report. Both older bind strings and structured bind mounts are checked, and a bind that appears in both is reported once, with a writable view winning over a read-only one. A root name or numeric UID zero is recognised even when a group is included, such as `0:1000`. Exposed but unpublished ports are not counted as published mappings. The summary is built from the findings across all containers, and the exit code is 1 when the highest severity meets the `--fail-on` threshold, which is high by default.

[Back to the project guide](../README.md)
