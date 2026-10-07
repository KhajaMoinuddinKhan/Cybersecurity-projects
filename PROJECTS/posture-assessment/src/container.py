"""The container assessor: Dockerfiles and compose files.

Reads the artifact as text and reasons about the instructions in it. There is no
Docker daemon involved and nothing is built, which is deliberate: the question is
whether the configuration describes something safe, and that is answerable from the
configuration. Building the image to ask would mean running the thing under
assessment.

The parser is small on purpose. It handles line continuations, comments and the
instruction set that the controls care about, and it does not attempt to evaluate
`ARG` substitutions -- so a value that arrives through a build argument is reported
as unread rather than assumed to be safe.
"""

from __future__ import annotations

import re
from pathlib import Path

from .findings import Evidence, make

__all__ = ["assess_dockerfile", "assess_compose", "assess_container", "parse_dockerfile"]

ENVIRONMENT = "container"

# Values that are obviously a placeholder rather than a credential. Reported
# separately from a real secret, because telling somebody their example password is
# a leak wastes their time and teaches them to ignore the check.
_PLACEHOLDER = re.compile(
    r"^(?:changeme|change-me|placeholder|example|sample|test|todo|xxx+|your[-_]?|"
    r"<[^>]+>|\$\{?[A-Z_]+\}?|.*not[-_]?a[-_]?secret.*)$", re.IGNORECASE)

_SECRET_KEY = re.compile(
    r"(?:password|passwd|pwd|secret|token|api[-_]?key|apikey|private[-_]?key|"
    r"access[-_]?key|auth)", re.IGNORECASE)

_SECRET_VALUE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|"                       # an AWS access key id
    r"ghp_[A-Za-z0-9]{20,}|"                      # a GitHub token
    r"sk-[A-Za-z0-9]{20,}|"                       # an OpenAI-shaped key
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"        # a private key
    r"[A-Za-z0-9+/]{40,}={0,2})")                 # a long opaque blob


def parse_dockerfile(text: str) -> list[tuple]:
    """The instructions, with continuations joined and comments dropped.

    Returns (instruction, argument, line number) so a finding can point at the line
    it came from rather than at the file.
    """
    instructions = []
    pending = ""
    start_line = 0
    for number, raw in enumerate(str(text or "").splitlines(), 1):
        line = raw.split("#", 1)[0] if raw.lstrip().startswith("#") else raw
        stripped = line.strip()
        if not stripped:
            continue
        if not pending:
            start_line = number
        if stripped.endswith("\\"):
            pending += stripped[:-1].strip() + " "
            continue
        combined = (pending + stripped).strip()
        pending = ""
        if not combined:
            continue
        parts = combined.split(None, 1)
        instructions.append((parts[0].upper(), parts[1].strip() if len(parts) > 1 else "",
                             start_line))
    if pending:
        parts = pending.split(None, 1)
        instructions.append((parts[0].upper(), parts[1].strip() if len(parts) > 1 else "",
                             start_line))
    return instructions


def _base_images(instructions) -> list[tuple]:
    images = []
    for name, argument, line in instructions:
        if name == "FROM":
            image = argument.split()[0] if argument else ""
            images.append((image, line))
    return images


def assess_dockerfile(policy, text: str, target: str = "Dockerfile") -> list:
    """Check one Dockerfile against every container control."""
    findings = []
    instructions = parse_dockerfile(text)
    names = [name for name, _, _ in instructions]

    # --- does it run as a non-root user? ---------------------------------
    control = policy.by_id("no-root-user")
    user_instructions = [(arg, line) for name, arg, line in instructions if name == "USER"]
    evidence = Evidence()
    if not user_instructions:
        evidence.add("instruction", "no USER instruction appears anywhere in the file", "")
        findings.append(make(
            control, ENVIRONMENT, target,
            "The image never names a user, so the process runs as whatever the base "
            "image set -- which for most base images is root.", evidence,
            location="%s: (no USER instruction)" % target))
    else:
        for argument, line in user_instructions:
            account = argument.split(":")[0].strip()
            if account in ("root", "0"):
                evidence.add("instruction", "line %d" % line, "USER %s" % argument)
        if evidence.items:
            findings.append(make(
                control, ENVIRONMENT, target,
                "A USER instruction names root, which is the account the control exists "
                "to remove.", evidence,
                location="%s:%d" % (target, user_instructions[0][1])))

    # --- is the base image pinned? ---------------------------------------
    control = policy.by_id("no-latest-tag")
    for image, line in _base_images(instructions):
        if not image or image.startswith("scratch"):
            continue
        tag = image.rsplit(":", 1)[1] if ":" in image.split("/")[-1] else ""
        if tag in ("", "latest") or "@" not in image and not tag:
            evidence = Evidence()
            evidence.add("instruction", "line %d" % line, "FROM %s" % image)
            evidence.add("observation",
                         "the tag is %s" % ("absent, which means latest" if not tag
                                            else "'latest'"), "")
            findings.append(make(
                control, ENVIRONMENT, target,
                "The base image is referenced by a tag that moves. Every other control "
                "here is a statement about a specific image, and a floating tag makes "
                "that statement expire without anything changing in this file.",
                evidence, location="%s:%d" % (target, line)))
            break

    # --- are secrets written into the configuration? ---------------------
    control = policy.by_id("no-secrets-in-configuration")
    for name, argument, line in instructions:
        if name not in ("ENV", "ARG"):
            continue
        for key, value in _env_pairs(argument):
            if not _SECRET_KEY.search(key):
                continue
            if _PLACEHOLDER.match(value.strip()) and not _SECRET_VALUE.search(value):
                continue
            evidence = Evidence()
            evidence.add("instruction", "line %d" % line, "%s %s" % (name, key))
            evidence.add("observation",
                         "the value is %s" % ("a long opaque string, which reads as a real "
                                              "credential" if _SECRET_VALUE.search(value)
                                              else "set to a literal rather than referenced"),
                         "")
            findings.append(make(
                control, ENVIRONMENT, target,
                "A value whose name says it is a credential is written into the image "
                "configuration. Anything in the image is in every copy of it, and "
                "removing the line later does not remove it from the layers already "
                "built.", evidence, location="%s:%d" % (target, line)))
            break

    # --- privileged and host namespaces, from the Dockerfile where present -
    control = policy.by_id("no-privileged-container")
    for name, argument, line in instructions:
        if name == "RUN" and "--privileged" in argument:
            evidence = Evidence()
            evidence.add("instruction", "line %d" % line, argument[:200])
            findings.append(make(
                control, ENVIRONMENT, target,
                "A build step asks for privileged access. The build then runs with the "
                "host's capabilities rather than the container's.", evidence,
                location="%s:%d" % (target, line)))
            break

    # A Dockerfile with no HEALTHCHECK is worth noting but is not one of the twelve
    # controls, so it is not reported. A check that reports things no control covers
    # is a check whose output nobody can act on.
    del names
    return findings


def _env_pairs(argument: str):
    """The KEY=value pairs in an ENV or ARG instruction, in either of its forms."""
    argument = argument.strip()
    if not argument:
        return []
    if "=" not in argument:
        return [(argument.split()[0], "")] if argument.split() else []
    pairs = []
    for piece in re.findall(r"(\w+)=(\"[^\"]*\"|'[^']*'|\S+)", argument):
        pairs.append((piece[0], piece[1].strip("\"'")))
    if not pairs:
        first = argument.split("=", 1)
        pairs.append((first[0].strip(), first[1].strip().strip("\"'")))
    return pairs


def assess_compose(policy, document: dict, target: str = "docker-compose.yml") -> list:
    """Check a compose file. The services are where the container controls live."""
    findings = []
    if not isinstance(document, dict):
        return findings
    services = document.get("services")
    if not isinstance(services, dict):
        return findings

    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        where = "%s: services.%s" % (target, name)

        if service.get("privileged") is True:
            evidence = Evidence()
            evidence.add("service", where, "privileged: true")
            findings.append(make(
                policy.by_id("no-privileged-container"), ENVIRONMENT, target,
                "The service runs privileged, which gives it the host's capabilities "
                "rather than the container's.", evidence, location=where))

        if str(service.get("network_mode") or "") == "host":
            evidence = Evidence()
            evidence.add("service", where, "network_mode: host")
            findings.append(make(
                policy.by_id("no-host-network"), ENVIRONMENT, target,
                "The service shares the host's network namespace, so the boundary the "
                "container was meant to provide is not there.", evidence, location=where))

        if service.get("read_only") is not True:
            evidence = Evidence()
            evidence.add("service", where, "read_only is %s"
                         % ("absent" if "read_only" not in service else service["read_only"]))
            findings.append(make(
                policy.by_id("read-only-root-filesystem"), ENVIRONMENT, target,
                "The root filesystem is writable, so anything that gets in can persist.",
                evidence, location=where))

        limits = service.get("deploy", {}).get("resources", {}).get("limits") \
            if isinstance(service.get("deploy"), dict) else None
        if not limits and not service.get("mem_limit") and not service.get("cpus"):
            evidence = Evidence()
            evidence.add("service", where, "no mem_limit, cpus or deploy.resources.limits")
            findings.append(make(
                policy.by_id("resource-limits-set"), ENVIRONMENT, target,
                "The service declares no resource limit, so it can consume the node.",
                evidence, location=where))

        if str(service.get("user") or "") in ("", "root", "0"):
            evidence = Evidence()
            evidence.add("service", where, "user is %s"
                         % ("absent" if not service.get("user") else service["user"]))
            findings.append(make(
                policy.by_id("no-root-user"), ENVIRONMENT, target,
                "The service does not name a user, so it runs as the image's default -- "
                "root, for most images.", evidence, location=where))

        image = str(service.get("image") or "")
        if image:
            tag = image.rsplit(":", 1)[1] if ":" in image.split("/")[-1] else ""
            if tag in ("", "latest"):
                evidence = Evidence()
                evidence.add("service", where, "image: %s" % image)
                findings.append(make(
                    policy.by_id("no-latest-tag"), ENVIRONMENT, target,
                    "The image tag moves, so what was assessed is not what runs.",
                    evidence, location=where))

        for key, value in (service.get("environment") or {}).items() \
                if isinstance(service.get("environment"), dict) else []:
            if _SECRET_KEY.search(str(key)) and not _PLACEHOLDER.match(str(value).strip()):
                evidence = Evidence()
                evidence.add("service", where, "environment: %s" % key)
                findings.append(make(
                    policy.by_id("no-secrets-in-configuration"), ENVIRONMENT, target,
                    "A credential is written into the compose file, which is a file in "
                    "version control.", evidence, location=where))
                break
        if isinstance(service.get("environment"), list):
            for item in service["environment"]:
                key, _, value = str(item).partition("=")
                if _SECRET_KEY.search(key) and not _PLACEHOLDER.match(value.strip()):
                    evidence = Evidence()
                    evidence.add("service", where, "environment: %s" % key)
                    findings.append(make(
                        policy.by_id("no-secrets-in-configuration"), ENVIRONMENT, target,
                        "A credential is written into the compose file, which is a file "
                        "in version control.", evidence, location=where))
                    break
    return findings


def assess_container(policy, path: str | Path) -> list:
    """Assess whatever container artifact the path points at."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError("no such artifact: %s" % path)
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.name.lower().endswith((".yml", ".yaml")):
        import yaml
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError:
            document = None
        return assess_compose(policy, document, target=path.name)
    return assess_dockerfile(policy, text, target=path.name)
