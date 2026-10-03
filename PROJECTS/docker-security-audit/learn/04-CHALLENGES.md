# Challenges

- The JSON snapshot may not describe later runtime changes.
- The default seccomp and AppArmor profiles are invisible in inspect output, so their absence is reported as neither good nor bad.
- An empty `Config.User` points at the image, which this tool does not read, so a named user is not resolved and the image's default is not proven to be root.
- Effective capabilities are not modelled; only `CapAdd` and `CapDrop` are read, so a `--privileged` container is caught by the privileged check rather than by the capability check.
- Secret detection is name-based and looks only at `Config.Env`, so it can both miss an unusually named secret and match an innocent variable.
- A published port is context, not proof of a problem; the check only reads the recorded `HostIp`, and a firewall or proxy can change what is actually reachable.
- Severity is a priority for review, not a verdict.
- The tool does not connect to the Docker daemon and never changes container settings.

## Working within the scope

These limits are the reason the report is written as evidence plus explanation rather than as a pass or fail. The interesting cases usually need a person: a docker socket mounted read-only is still the Docker socket, a published port may be intentional, and a floating tag may be a deliberate choice during development. The tool gives the field, the fact and the reasoning, and leaves the decision open.

Compare the supplied fixture's two containers. The web app triggers findings at all three severities while the cache triggers none, and a single changed field — dropping `ALL` from `CapDrop` — moves the cache without any change to its name or image. That is the behaviour to keep in mind: the report follows the configuration in the JSON, and nothing more.

[Back to the project guide](../README.md)
