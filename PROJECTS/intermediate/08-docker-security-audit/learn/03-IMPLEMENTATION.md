# Implementation

- The audit checks `HostConfig`, `NetworkSettings`, and `Config` fields.
- Sensitive bind mounts are identified from the host-side path.
- Host namespace settings produce medium-severity findings.
- Privileged mode and sensitive host mounts produce high-severity findings.
- An empty configured user produces a review item because the image default may be root.
