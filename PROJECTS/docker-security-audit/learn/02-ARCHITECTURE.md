# Architecture

1. The command line accepts a saved Docker inspect JSON file.
2. `load_json()` accepts either one inspect object or Docker's list form.
3. `audit_container()` reads host, network, and container configuration fields.
4. Each matched rule produces a severity and message.
5. The command line prints the findings.

## Follow one run

The loader validates the JSON structure, and `audit_container()` inspects `HostConfig`, `NetworkSettings`, `Config`, and `Mounts`. Both older bind strings and structured bind mounts are checked. A root name or numeric UID zero is recognized even when a group is included, such as `0:1000`. Exposed but unpublished ports are not counted as published mappings.

Use the included fixture to explore the report, or save `docker inspect CONTAINER` output as UTF-8 JSON and pass that file instead. Both a single inspect object and a list of containers are accepted. Every container in a list is reviewed and labeled in the output.

[Back to the project guide](../README.md)
