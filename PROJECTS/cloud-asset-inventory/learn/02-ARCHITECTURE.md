# Architecture

1. The command line accepts one or more files, directories of exports, or a mix of both.
2. Each input path is expanded in order: a file is taken as-is, a directory contributes its `.json` files, and anything else becomes a per-file error.
3. `load_export()` reads one file as UTF-8 (accepting a byte order mark) and parses it.
4. `detect_format()` names the shape from the document structure.
5. The matching adapter maps every record into an `Asset`, counting records that cannot be mapped.
6. `build_report()` sorts the assets into a stable order and runs `build_findings()`.
7. The report is rendered as text, or emitted as one JSON document with `--json`, and optionally written to JSON and CSV files.

## Follow one run

`build_report()` walks the inputs and, for each file, records a `FileReport` — the detected format, how many assets were parsed, how many records were skipped, and an error if the file could not be read or recognised. A bad file becomes one error line and the run continues; only a file that is never reached stops nothing, because nothing is fatal to the batch.

Detection is structural. A top-level `value` array is an Azure Resource Graph export; a top-level list under `resourceIdentifiers`, `results`, `Results`, `configurationItems` or `ConfigurationItems` is an AWS Config resource list; a top-level `assets` array whose records carry `assetType` is a GCP asset inventory, one whose records carry `provider` is the generic shape. Assets are sorted by provider, resource type, name and identifier so the table and the findings are reproducible.

The bundled files contain synthetic training data. An actual export must already be in one of these shapes; the adapters map fields, they do not fetch anything.

[Back to the project guide](../README.md)
