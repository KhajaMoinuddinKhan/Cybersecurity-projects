# Challenges

- The JSON snapshot may not describe later runtime changes.
- A published port is context, not proof of a security problem.
- The project covers a small rule set rather than every Docker hardening option.
- The tool does not connect to the Docker daemon or change container settings.

## Working within the scope

This is a snapshot review with a small rule set. It does not inspect image vulnerabilities, secrets, effective runtime identities, capabilities, seccomp, or every mount type. A named user cannot be resolved to a UID without inspecting the image. A published port may be intentional; review its bindings and reachability in context.

Compare the supplied fixture with a copy that sets `Privileged` to `true` or `Config.User` to `root`. Then place both objects in one JSON list. The report should show each container separately and retain the distinct reasons for review.

[Back to the project guide](../README.md)
