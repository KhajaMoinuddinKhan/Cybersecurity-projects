# Overview

Docker Security Audit reads saved Docker inspect JSON and reports configuration risks as a prioritised list of findings. Each finding carries a severity, a one-line piece of evidence, a plain-language explanation and, where one applies, a CIS Docker Benchmark style control reference. The report ends with a count by severity, and a `--json` mode returns the same information as a document.

It reads the container configuration: privileged mode, host network, PID and IPC namespace sharing, added and dropped capabilities, the root filesystem mode, seccomp and AppArmor settings, the configured user, sensitive bind mounts, published ports, image references, health checks, restart policies, resource limits, secret-looking environment variables and log settings. A file may hold one inspect object, a list of them, or Docker's own output for several containers, and several files may be passed at once.

## A useful first exercise

The bundled fixture holds two containers: a misconfigured web app and a hardened cache. Run the tool and note how the web app produces findings at all three severities while the cache produces none. Then change one field — set the cache's `CapDrop` to `[]` — and watch the default-capability finding appear, which is a small demonstration of how the report follows the configuration rather than the container's name.

This is a snapshot review with a deliberately narrow rule set. It never contacts the daemon, so it cannot see anything that changed after the JSON was written. It does not read the image, so it cannot resolve a user name to a UID or prove that an image's default user is root, and it cannot scan for vulnerabilities or secrets outside `Config.Env`. The default seccomp and AppArmor profiles are not recorded in inspect output, so those checks only fire when the output explicitly says `unconfined`.

[Back to the project guide](../README.md)
