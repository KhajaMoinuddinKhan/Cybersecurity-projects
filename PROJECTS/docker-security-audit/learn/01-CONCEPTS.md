# Concepts

- Container isolation depends on namespace, privilege, mount, and user settings.
- Privileged mode grants broad host access and deserves close review.
- Sharing host network, PID, or IPC namespaces reduces isolation.
- Mounting the host root filesystem or Docker socket gives a container powerful access.
- Published ports and the configured user add useful exposure and privilege context.

## Interpreting the evidence

Findings include privileged mode, shared host namespaces, host-root and Docker-socket bind mounts, published ports, and an unspecified or explicitly root user. The sample reports a published port and an unspecified user. The severities are priorities for review, not proof that a container has been compromised.

This is a snapshot review with a small rule set. It does not inspect image vulnerabilities, secrets, effective runtime identities, capabilities, seccomp, or every mount type. A named user cannot be resolved to a UID without inspecting the image. A published port may be intentional; review its bindings and reachability in context.

[Back to the project guide](../README.md)
