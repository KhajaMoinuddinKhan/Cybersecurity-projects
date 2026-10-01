# Docker Security Audit

`docker inspect` produces a lot of JSON, and the risky parts are scattered through it: a privileged container here, a host namespace there, a socket mounted into a container somewhere else. This tool reads that JSON and prints a short list of explainable findings per container.

It reads saved inspect output. It never talks to the Docker daemon, never starts or stops a container, and never needs the Docker CLI installed.

## Running it

Standard library only:

```console
docker inspect my-container > inspect.json
python -m src.audit inspect.json
```

The bundled fixture produces two findings:

```
Container: 1
[LOW] 1 published port mapping(s) require review.
[MEDIUM] Container does not explicitly declare a non-root user.
```

A file may contain a single inspect object or a list of them; every container in the file is reviewed, and the report is validated before any of it is printed, so a malformed entry does not leave you reading half a report.

## What it looks for

| Finding | Why it matters |
| --- | --- |
| `Privileged: true` | The container effectively shares the host kernel's capabilities. |
| `NetworkMode`, `PidMode`, `IpcMode` set to `host` | The container can see or affect host resources outside its own namespace. |
| A bind mount of `/` (or a Windows drive root such as `C:`) | The host filesystem is mounted into the container. |
| A bind mount of `docker.sock` | Anything in the container can control the daemon, which is root on the host. |
| `Config.User` missing or empty | The image does not state which user it runs as. |
| `Config.User` set to root or UID 0 | It does state it, and the answer is root. |
| Published ports | Each one is an entry point that deserves a look. |

The difference between "does not declare a user" and "explicitly runs as root" is kept, because they lead to different conversations. A numeric `0` counts as a declaration, and a Windows path like `C:\data:/container` is parsed with its drive letter intact rather than being split at the first colon.

## Reading the findings

Severity here means "how much attention this deserves", not "this container is compromised". A privileged container in a lab is a normal thing to find. A docker socket mounted into a container that also has a published port is a much more interesting one. The tool gives you the facts and the reasoning; deciding what matters is still your job.

## Tests

```console
python -m pytest -q tests
```

Tests cover privileged mode, host namespaces, sensitive mounts, published ports, explicit and numeric root users, structured mounts, multiple containers, Windows drive-letter binds, and malformed inspect data.
