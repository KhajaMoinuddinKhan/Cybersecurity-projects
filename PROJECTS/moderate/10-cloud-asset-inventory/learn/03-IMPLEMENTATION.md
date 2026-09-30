# Implementation

- `REQUIRED_TAGS` defines the Owner and Environment metadata expected by the project.
- Public assets produce a medium-severity review item.
- Missing or malformed tags produce low-severity metadata findings.
- Assets without a region produce a separate low-severity finding.
- Provider, type, and name values are printed for each inventory record.
