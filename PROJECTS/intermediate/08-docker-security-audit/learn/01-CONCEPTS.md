# Concepts

- Container isolation depends on namespace, privilege, mount, and user settings.
- Privileged mode grants broad host access and deserves close review.
- Sharing host network, PID, or IPC namespaces reduces isolation.
- Mounting the host root filesystem or Docker socket gives a container powerful access.
- Published ports and the configured user add useful exposure and privilege context.
