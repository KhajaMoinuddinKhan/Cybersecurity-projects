# Concepts

- An asset inventory records what resources exist and gives analysts a consistent review point.
- Exports arrive in provider-specific shapes; an adapter turns each shape into one normalised record so the same checks apply everywhere.
- Auto-detection reads the document structure — the top-level key and the fields on the records — rather than trusting a file name or a flag.
- Public exposure, encryption state, ownership and environment tags, and region data are the evidence the findings are built from.
- A value that is absent and a value that is present-but-wrong are different problems: absence is "not recorded", a wrong type is a data-quality error.

## Interpreting the evidence

Each record becomes an asset with `provider`, `resource_type`, `identifier`, `name`, `region`, `tags`, `public` and `encrypted`. `public` and `encrypted` can be `true`, `false`, or `null`; null means the export did not record that state. The command prints the inventory table and the counts first, then findings labelled with a severity, a category and the asset name.

Publicly exposed assets and unencrypted storage get a medium-severity review item. Missing tags, missing Owner or Environment tags, missing regions, and malformed values get low-severity findings. Owner and Environment are matched case-insensitively so that lower-case labels from GCP still count. A resource can produce more than one finding.

The program does not authenticate to a cloud provider or discover resources. It reviews only the data you give it, which can be incomplete or out of date. A public flag does not describe actual firewall reachability, and a populated tag can still contain incorrect information. Global resources may legitimately need a different region policy.

[Back to the project guide](../README.md)
