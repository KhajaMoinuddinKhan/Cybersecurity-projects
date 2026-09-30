# Concepts

- A security event record needs consistent fields so analysts can filter and compare entries.
- Severity values are normalized before storage to keep queries predictable.
- Parameterized SQL keeps user input separate from SQL syntax.
- Literal search escaping prevents `%` and `_` from acting as unintended SQL wildcards.
- Synthetic events make the dashboard safe to run as a local portfolio project.
