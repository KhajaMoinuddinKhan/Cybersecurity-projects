# Docker Security Audit

`docker inspect` produces a lot of JSON, and the risky parts are scattered through it: a privileged container here, a host namespace there, a socket mounted into a container somewhere else. This tool reads that JSON and prints a prioritised list of explainable findings per container.

It reads saved inspect output. It never talks to the Docker daemon, never starts or stops a container, and never needs the Docker CLI installed.

## Running it

Standard library only:

```console
docker inspect my-container > inspect.json
python -m src.audit inspect.json
```

Docker's output for several containers is already a JSON array, so it can be saved and passed in directly. A file may also hold a single inspect object, and several files may be given at once:

```console
docker inspect web db > fleet.json
python -m src.audit fleet.json
python -m src.audit web.json db.json
```

Add `--json` for a machine-readable report:

```console
python -m src.audit --json inspect.json
```

The command exits with status 1 when any high-severity finding is present, so it can gate a pipeline. `--fail-on medium`, `--fail-on low` or `--fail-on none` change that threshold.

The bundled fixture holds two containers: a deliberately misconfigured web app and a hardened cache. It prints:

```

Container: /web-app
[HIGH] HostConfig.NetworkMode is "host".
    The container shares the host network namespace instead of its own.
    Control: CIS Docker Benchmark 5.9
[HIGH] HostConfig.PidMode is "host".
    The container shares the host PID namespace instead of its own.
    Control: CIS Docker Benchmark 5.15
[MEDIUM] HostConfig.IpcMode is "host".
    The container shares the host IPC namespace instead of its own.
    Control: CIS Docker Benchmark 5.13
[HIGH] HostConfig.CapAdd includes SYS_ADMIN.
    The container can mount filesystems, change kernel settings and often escape isolation.
    Control: CIS Docker Benchmark 5.3
[HIGH] HostConfig.CapAdd includes NET_ADMIN.
    The container can reconfigure network interfaces, routes and firewall rules.
    Control: CIS Docker Benchmark 5.3
[LOW] HostConfig.CapDrop does not include ALL.
    The container keeps the Docker default capability set instead of dropping everything and adding back only what it needs.
    Control: CIS Docker Benchmark 5.3
[LOW] HostConfig.ReadonlyRootfs is not true.
    The container's root filesystem is writable, so a compromised process can change binaries and configuration on it.
[HIGH] seccomp is set to unconfined.
    The container runs without the default seccomp filter, so it can call every system call the kernel allows.
    Control: CIS Docker Benchmark 5.10
[MEDIUM] AppArmor is set to unconfined.
    The container runs without an AppArmor profile, removing an extra layer of mandatory access control.
    Control: CIS Docker Benchmark 5.1
[MEDIUM] Config.User is empty.
    The container does not declare a user, so it runs as whatever the image's USER sets, which is root when the image sets none.
    Control: CIS Docker Benchmark 4.1
[HIGH] Sensitive bind mount of /var/run/docker.sock (read-write).
    The container can reach the Docker socket, which is root on the host; the mount is read-write.
    Control: CIS Docker Benchmark 5.31
[MEDIUM] Sensitive bind mount of /etc (read-only).
    The container can reach the host /etc directory; the mount is read-only.
    Control: CIS Docker Benchmark 5.5
[MEDIUM] Published on all interfaces: 0.0.0.0:8080->8080/tcp.
    These port mappings are bound to 0.0.0.0 (or ::), so they are reachable from every network the host is on, not only from loopback.
[LOW] Image "nginx:latest" uses the latest tag.
    The latest tag is movable, so the image can change between runs; pin a version or a digest for reproducibility.
[LOW] Config.Healthcheck is absent.
    No health check is defined, so Docker cannot tell a running container from a healthy one.
    Control: CIS Docker Benchmark 5.26
[LOW] HostConfig.RestartPolicy is "always".
    The container is restarted unconditionally, including after a host reboot, which can keep a misbehaving container running.
[LOW] HostConfig.Memory is not set.
    No memory limit is configured, so the container can consume all host memory and affect other workloads.
    Control: CIS Docker Benchmark 5.11
[LOW] No CPU quota is set.
    NanoCpus and CpuQuota are both unset, so the container has no CPU ceiling.
    Control: CIS Docker Benchmark 5.12
[MEDIUM] Secret-looking environment variables hold values: DB_PASSWORD.
    Environment values are stored in the container configuration and are readable by anyone who can run docker inspect; use Docker secrets or an external store instead.
[LOW] Log driver has no size limit.
    No max-size or max-file is set, so container logs grow without bound on the host disk.

Container: /cache
No configured checks were triggered.

Summary: HIGH 6, MEDIUM 6, LOW 8
```

Every container in every file is reviewed before any of the report is printed, so a malformed entry does not leave you reading half a report.

## What it looks for

| Check | Control | Why it matters |
| --- | --- | --- |
| `HostConfig.Privileged` is true | 5.4 | The container has all capabilities and unrestricted device access. |
| `NetworkMode`, `PidMode`, `IpcMode` set to `host` | 5.9, 5.15, 5.13 | The container shares a host namespace instead of its own. |
| `CapAdd` includes a dangerous capability | 5.3 | Each one is named on its own, with a line about what it grants (`SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH`, `SYS_MODULE` and others). `ALL` is called out separately. |
| `CapDrop` does not include `ALL` | 5.3 | The Docker default capability set is kept rather than dropped and added back selectively. |
| `ReadonlyRootfs` is not true | — | A compromised process can write to the container's own filesystem. |
| `SecurityOpt` or `AppArmorProfile` says `unconfined` | 5.10, 5.1 | seccomp or AppArmor has been switched off. |
| `Config.User` is empty or root | 4.1 | The container runs as root, or the image's default decides and that default is often root. |
| A bind mount of the Docker socket | 5.31 | Anything in the container can drive the daemon, which is root on the host. |
| A bind mount of `/`, `/etc`, `/proc`, `/sys`, `/dev` | 5.5 | The host filesystem or its device and process views are reachable. Read-only mounts are reported one step lower than writable ones. |
| A published port bound to `0.0.0.0` or `::` | — | The port is reachable from every network the host is on. Loopback-only bindings are not flagged. |
| An image tag of `latest` or no tag at all | — | A floating reference can change between runs; a digest pin does not trigger anything. |
| `Config.Healthcheck` absent or `Test` is `NONE` | 5.26 | Docker cannot tell a running container from a healthy one. |
| Restart policy `always`, or absent | — | The container is restarted unconditionally, including after a host reboot. |
| No memory limit (`Memory` unset) | 5.11 | The container can consume all host memory. |
| No CPU quota (`NanoCpus` and `CpuQuota` unset) | 5.12 | The container has no CPU ceiling. |
| Secret-looking environment variables with values | — | `PASSWORD`, `SECRET`, `TOKEN`, `KEY` and `CREDENTIAL` names are reported with their names only, never their values. |
| A non-default log driver, or no log size limit | — | Logs go to the host or a remote system, or grow without bound on the host disk. |

The difference between "does not declare a user" and "explicitly runs as root" is kept, because they lead to different conversations. A numeric `0` counts as a declaration, and a Windows path like `C:\data:/container` is parsed with its drive letter intact rather than being split at the first colon. A bind that appears in both `HostConfig.Binds` and `Mounts` is reported once.

## Reading the findings

Each finding carries a severity, a one-line piece of evidence, a plain-language explanation and, where one applies, a CIS Docker Benchmark style control reference. The command prints a summary count by severity at the end, and `--json` returns the same information as a document with `containers` and `summary` keys.

Severity here means "how much attention this deserves", not "this container is compromised". A privileged container in a lab is a normal thing to find. A docker socket mounted into a container that also publishes a port is a much more interesting one. The tool gives you the facts and the reasoning; deciding what matters is still your job.

## Limits

This is a snapshot review of saved JSON, and the checks are deliberately narrow. The honest boundaries:

- It never contacts the Docker daemon, so it cannot see anything that changed after the inspect output was written.
- seccomp and AppArmor are only flagged when the output explicitly says `unconfined`. Docker does not record the default profile in inspect output, so a container with no security options is reported as neither good nor bad.
- An empty `Config.User` means the image's `USER` decides, and that is often root, but the image is not read here, so a named user is not resolved to a UID and the default is not proven to be root.
- Capability checks read `CapAdd` and `CapDrop` only. They do not model the effective capability set (for example a `--privileged` container or a device cgroup).
- Secret detection is name-based on `Config.Env`. It will miss unusual names and can match innocent ones, and it only looks at environment variables, not files or image layers.
- The port check reads the recorded `HostIp`. A port bound to loopback may still be reachable through a host firewall or proxy, and a port bound to `0.0.0.0` may be blocked by one.
- The image check only looks at the reference string in `Config.Image`; it does not verify that a digest exists or that the image has not changed.
- "No configured checks were triggered" means exactly that, not that the container is hardened.

## Tests

```console
python -m pytest -q tests
```

Tests cover privileged mode, host network, PID and IPC namespaces, each dangerous capability and `CapAdd ALL`, the default capability set, a writable root filesystem, seccomp and AppArmor `unconfined`, empty and explicit root users, Docker socket and `/etc`/`/proc`/`/sys`/`/dev` mounts with read-only versus read-write, duplicate bind reporting, ports on `0.0.0.0` versus loopback, floating and digest-pinned images, health checks, restart policies, memory and CPU limits, secret-looking environment variables, log drivers and log limits, multiple files and multiple containers, JSON output, the severity summary and the exit code.
