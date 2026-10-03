# Concepts

- Container isolation rests on namespaces, capabilities, mounts, and the user and resource settings.
- Privileged mode, host namespaces and added capabilities each weaken that isolation in a different way.
- Capabilities are named individually because `SYS_ADMIN` and `DAC_READ_SEARCH` grant very different powers, and a reader deserves to see which one was added.
- The default capability set is itself a decision: a container that does not drop `ALL` keeps a set the operator never chose.
- A sensitive host path is either read-write or read-only, and that difference changes how much attention it deserves.
- Exposure has two faces here: what the container can reach (the socket, the host filesystem) and what can reach it (a port published on every interface).
- Severity is a review priority, not a verdict about the container.

## Interpreting the evidence

Each finding pairs a severity with the field it came from, a sentence about what that field means, and a control reference where one applies. The sample web app shows the pattern: host namespaces and a dangerous capability are high, a read-only `/etc` mount and a port on every interface are medium, and a floating image tag and a missing health check are low. The cache container shows the opposite configuration — dropping `ALL`, a read-only root filesystem, a digest-pinned image and a bounded log driver — and so has nothing to report.

The severities are priorities for review, not proof that a container has been compromised. A privileged container in a lab is normal; a docker socket mounted into a container that also publishes a port is worth a longer look. The tool supplies the facts and the reasoning, and the judgement stays with the reader.

[Back to the project guide](../README.md)
