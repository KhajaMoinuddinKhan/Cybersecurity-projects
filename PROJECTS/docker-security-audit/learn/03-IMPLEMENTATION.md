# Implementation

- The audit checks `HostConfig`, `NetworkSettings`, and `Config` fields.
- Sensitive bind mounts are identified from the host-side path.
- Host namespace settings produce medium-severity findings.
- Privileged mode and sensitive host mounts produce high-severity findings.
- An empty configured user produces a review item because the image default may be root.

## Inputs and failure handling

Use the included fixture to explore the report, or save `docker inspect CONTAINER` output as UTF-8 JSON and pass that file instead. Both a single inspect object and a list of containers are accepted. Every container in a list is reviewed and labeled in the output.

If Docker is unavailable, you can still review a previously saved inspect file. Invalid nested structures produce an error before a partial report is shown. If no checks trigger, read that as “none of these configured checks matched,” not as a complete hardening assessment.

[Back to the project guide](../README.md)
