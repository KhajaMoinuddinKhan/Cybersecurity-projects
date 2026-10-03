# Implementation

- Each check is a small function that takes the relevant config section and appends a `Finding` dataclass.
- `HostConfig` drives privileged mode, namespace sharing, capabilities, the root filesystem, security options, restart policy, resource limits and logging.
- `Config` drives the user, the image reference, environment variables and the health check.
- Sensitive bind mounts are identified from the host-side path, and read-only filesystem mounts are downgraded one severity step, while the Docker socket stays high because a socket is still usable when the bind is marked read-only.
- `DANGEROUS_CAPABILITIES` and `SENSITIVE_HOST_PATHS` are tables, so the wording for each capability and each host path lives in one place and a new entry is a one-line change.
- `_object` and `_list` validate shapes and raise `ValueError`, which the command turns into a single "Could not review inspect data" message rather than a traceback.
- Secret detection splits each environment variable name into tokens and compares them against a small list, so `DB_PASSWORD` and `AWS_SECRET_ACCESS_KEY` match while `MONKEY` does not. Only the names are reported, never the values.

## Inputs and failure handling

Use the included fixture to explore the report, or save `docker inspect CONTAINER` output as UTF-8 JSON and pass that file instead. A single inspect object, a list of containers, and Docker's own multi-container output are all accepted, as are several files at once. Every container in a file is reviewed and labelled in the output.

The `--json` mode emits a document with a `containers` array and a `summary` object, where each finding has `severity`, `evidence`, `explanation` and `control` fields. The exit code is 1 when a high-severity finding is present, and `--fail-on medium`, `--fail-on low` or `--fail-on none` change that threshold. If no checks trigger, read that as "none of these configured checks matched", not as a complete hardening assessment.

[Back to the project guide](../README.md)
