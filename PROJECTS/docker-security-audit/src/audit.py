"""Review saved Docker inspect data without contacting the daemon."""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Review priorities, highest first. Severity ranks how much attention a finding
# deserves, not whether a container has actually been compromised.
SEVERITIES = ("HIGH", "MEDIUM", "LOW")
SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Capabilities that give a container a host-level power. Each added capability
# is reported on its own so the reader can see exactly what was granted.
DANGEROUS_CAPABILITIES: dict[str, tuple[str, str]] = {
    "SYS_ADMIN": ("HIGH", "mount filesystems, change kernel settings and often escape isolation"),
    "SYS_PTRACE": ("HIGH", "trace and read the memory of other processes, including on the host"),
    "SYS_MODULE": ("HIGH", "load and unload kernel modules"),
    "SYS_RAWIO": ("HIGH", "access raw I/O ports directly"),
    "DAC_READ_SEARCH": ("HIGH", "read any file regardless of its permissions"),
    "DAC_OVERRIDE": ("HIGH", "write any file regardless of its permissions"),
    "MAC_ADMIN": ("HIGH", "change mandatory access control (SELinux/AppArmor) settings"),
    "MAC_OVERRIDE": ("HIGH", "bypass mandatory access control policies"),
    "AUDIT_CONTROL": ("HIGH", "change the kernel's audit rules"),
    "NET_ADMIN": ("HIGH", "reconfigure network interfaces, routes and firewall rules"),
    "NET_RAW": ("MEDIUM", "craft raw packets and spoof addresses"),
    "SETUID": ("MEDIUM", "assume any user identity"),
    "SETGID": ("MEDIUM", "assume any group identity"),
    "SYS_CHROOT": ("MEDIUM", "call chroot and disguise the filesystem root"),
    "MKNOD": ("MEDIUM", "create device nodes such as raw disks"),
    "AUDIT_WRITE": ("MEDIUM", "write to the kernel audit log"),
    "BLOCK_SUSPEND": ("MEDIUM", "block the host from suspending"),
}

# Host paths that should not be bind-mounted into a container. The value is the
# review priority for a writable mount; a read-only filesystem mount is one step
# lower. The Docker socket keeps its priority either way, because a socket is
# still usable when the bind is marked read-only.
SENSITIVE_HOST_PATHS: dict[str, tuple[str, str]] = {
    "/etc": ("HIGH", "the host /etc directory"),
    "/root": ("HIGH", "the host root user's home directory"),
    "/proc": ("HIGH", "the host /proc filesystem"),
    "/sys": ("MEDIUM", "the host /sys filesystem"),
    "/dev": ("MEDIUM", "the host /dev filesystem"),
    "/boot": ("MEDIUM", "the host /boot directory"),
}

# Log drivers that keep records somewhere other than the container's own disk.
EXTERNAL_LOG_DRIVERS = {
    "syslog",
    "journald",
    "fluentd",
    "gelf",
    "awslogs",
    "splunk",
    "etwlogs",
    "gcplogs",
    "logentries",
    "nats",
}

# Environment variable name fragments that suggest a stored secret.
SECRET_NAME_TOKENS = ("PASSWORD", "PASSWD", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "APIKEY")


@dataclass(frozen=True)
class Finding:
    """One explainable review item for a container."""

    severity: str
    evidence: str
    explanation: str
    control: str | None = None


def _object(info: dict[str, Any], key: str) -> dict[str, Any]:
    value = info.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be a JSON object")
    return value


def _list(info: dict[str, Any], key: str) -> list[Any]:
    value = info.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a JSON array")
    return value


def bind_spec(binding: str) -> tuple[str, bool]:
    """Return the (host path, read-only) of a bind spec, keeping a Windows drive letter."""

    parts = binding.split(":")
    if (
        len(parts) >= 2
        and len(parts[0]) == 1
        and parts[0].isalpha()
        and parts[1][:1] in {"\\", "/", ""}
    ):
        source = f"{parts[0]}:{parts[1]}"
        options = parts[2:]
    else:
        source = parts[0]
        options = parts[1:]
    flags = ",".join(options).split(",")
    return source, "ro" in flags


def bind_source(binding: str) -> str:
    """Return the host path of a bind spec, keeping a Windows drive letter."""

    return bind_spec(binding)[0]


def is_host_root(source: str) -> bool:
    """True for a filesystem root: "/", "\\" or a bare drive such as "C:"."""

    stripped = source.rstrip("/\\")
    if not stripped:
        return True
    return len(stripped) == 2 and stripped[0].isalpha() and stripped[1] == ":"


def _normalise_source(source: str) -> str:
    return source.rstrip("/\\") or "/"


def sensitive_mount(source: str) -> tuple[str, str, str] | None:
    """Return (label, description, severity) when a bind source is sensitive."""

    if is_host_root(source):
        return "/", "the host root filesystem", "HIGH"
    if source.endswith("/docker.sock"):
        return "/var/run/docker.sock", "the Docker socket, which is root on the host", "HIGH"
    normalised = _normalise_source(source)
    for path, (severity, description) in SENSITIVE_HOST_PATHS.items():
        if normalised == path:
            return path, description, severity
    return None


def _collect_mounts(info: dict[str, Any]) -> list[tuple[str, bool]]:
    """Return every bind mount as (host source, read-only), de-duplicated."""

    host = _object(info, "HostConfig")
    mounts: dict[str, bool] = {}

    def add(source: str, read_only: bool) -> None:
        key = _normalise_source(source)
        # The same bind can appear in Binds and Mounts; a writable view wins.
        mounts[key] = mounts.get(key, True) and read_only

    bindings = _list(host, "Binds")
    if not all(isinstance(item, str) for item in bindings):
        raise ValueError("HostConfig.Binds must be a list of strings")
    for binding in bindings:
        source, read_only = bind_spec(binding)
        # An empty host path is not a bind and must not be read as "/".
        if source:
            add(source, read_only)

    # Docker records --mount bind mounts here even when HostConfig.Binds is empty.
    structured = _list(info, "Mounts")
    if not all(isinstance(item, dict) for item in structured):
        raise ValueError("Mounts must be a list of objects")
    for mount in structured:
        if mount.get("Type") == "bind":
            source = mount.get("Source")
            if not isinstance(source, str) or not source:
                raise ValueError("Bind mount Source must be nonempty text")
            read_only = mount.get("RW") is False or str(mount.get("Mode", "")).startswith("ro")
            add(source, read_only)

    return list(mounts.items())


def _positive(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _downgrade(severity: str) -> str:
    return "MEDIUM" if severity == "HIGH" else "LOW"


def _check_privileged(host: dict[str, Any], findings: list[Finding]) -> None:
    if host.get("Privileged") is True:
        findings.append(
            Finding(
                "HIGH",
                "HostConfig.Privileged is true.",
                "A privileged container has all Linux capabilities and unrestricted device access, so it can usually reach the host kernel.",
                "CIS Docker Benchmark 5.4",
            )
        )


def _check_namespaces(host: dict[str, Any], findings: list[Finding]) -> None:
    namespaces = (
        ("NetworkMode", "network", "HIGH", "5.9"),
        ("PidMode", "PID", "HIGH", "5.15"),
        ("IpcMode", "IPC", "MEDIUM", "5.13"),
    )
    for setting, namespace, severity, control in namespaces:
        value = host.get(setting)
        if value == "host":
            findings.append(
                Finding(
                    severity,
                    f'HostConfig.{setting} is "host".',
                    f"The container shares the host {namespace} namespace instead of its own.",
                    f"CIS Docker Benchmark {control}",
                )
            )
        elif isinstance(value, str) and value.startswith("container:"):
            findings.append(
                Finding(
                    "MEDIUM",
                    f'HostConfig.{setting} is "{value}".',
                    f"The container shares another container's {namespace} namespace.",
                    None,
                )
            )


def _check_capabilities(host: dict[str, Any], findings: list[Finding]) -> None:
    added = _list(host, "CapAdd")
    if not all(isinstance(item, str) for item in added):
        raise ValueError("HostConfig.CapAdd must be a list of strings")
    for capability in added:
        name = capability.upper()
        if name == "ALL":
            findings.append(
                Finding(
                    "HIGH",
                    "HostConfig.CapAdd includes ALL.",
                    "The container is granted every capability the kernel offers.",
                    "CIS Docker Benchmark 5.3",
                )
            )
            continue
        entry = DANGEROUS_CAPABILITIES.get(name)
        if entry is not None:
            severity, effect = entry
            findings.append(
                Finding(
                    severity,
                    f"HostConfig.CapAdd includes {name}.",
                    f"The container can {effect}.",
                    "CIS Docker Benchmark 5.3",
                )
            )
        else:
            findings.append(
                Finding(
                    "MEDIUM",
                    f"HostConfig.CapAdd includes {name}.",
                    "An extra capability is granted beyond the Docker default set.",
                    "CIS Docker Benchmark 5.3",
                )
            )

    dropped = _list(host, "CapDrop")
    if not all(isinstance(item, str) for item in dropped):
        raise ValueError("HostConfig.CapDrop must be a list of strings")
    if not any(item.upper() == "ALL" for item in dropped):
        findings.append(
            Finding(
                "LOW",
                "HostConfig.CapDrop does not include ALL.",
                "The container keeps the Docker default capability set instead of dropping everything and adding back only what it needs.",
                "CIS Docker Benchmark 5.3",
            )
        )


def _check_root_filesystem(host: dict[str, Any], findings: list[Finding]) -> None:
    if host.get("ReadonlyRootfs") is not True:
        findings.append(
            Finding(
                "LOW",
                "HostConfig.ReadonlyRootfs is not true.",
                "The container's root filesystem is writable, so a compromised process can change binaries and configuration on it.",
                None,
            )
        )


def _check_security_profiles(host: dict[str, Any], findings: list[Finding]) -> None:
    options = _list(host, "SecurityOpt")
    if not all(isinstance(item, str) for item in options):
        raise ValueError("HostConfig.SecurityOpt must be a list of strings")
    normalised = [item.strip().lower() for item in options]

    seccomp_profile = host.get("SeccompProfile")
    seccomp_off = any(
        item.startswith("seccomp=unconfined") or item.startswith("seccomp:unconfined")
        for item in normalised
    ) or (isinstance(seccomp_profile, str) and seccomp_profile.lower() == "unconfined")
    if seccomp_off:
        findings.append(
            Finding(
                "HIGH",
                "seccomp is set to unconfined.",
                "The container runs without the default seccomp filter, so it can call every system call the kernel allows.",
                "CIS Docker Benchmark 5.10",
            )
        )

    apparmor_profile = host.get("AppArmorProfile")
    apparmor_off = any(
        item.startswith("apparmor=unconfined") or item.startswith("apparmor:unconfined")
        for item in normalised
    ) or (isinstance(apparmor_profile, str) and apparmor_profile.lower() == "unconfined")
    if apparmor_off:
        findings.append(
            Finding(
                "MEDIUM",
                "AppArmor is set to unconfined.",
                "The container runs without an AppArmor profile, removing an extra layer of mandatory access control.",
                "CIS Docker Benchmark 5.1",
            )
        )


def _check_user(config: dict[str, Any], findings: list[Finding]) -> None:
    # A numeric UID 0 is a real declaration, so only None means "not declared".
    raw_user = config.get("User")
    user = "" if raw_user is None else str(raw_user).strip().split(":", 1)[0]
    if not user:
        findings.append(
            Finding(
                "MEDIUM",
                "Config.User is empty.",
                "The container does not declare a user, so it runs as whatever the image's USER sets, which is root when the image sets none.",
                "CIS Docker Benchmark 4.1",
            )
        )
    elif user == "root" or (user.isdecimal() and int(user) == 0):
        findings.append(
            Finding(
                "MEDIUM",
                "Config.User is root (UID 0).",
                "The container is explicitly configured to run as the root user inside the container.",
                "CIS Docker Benchmark 4.1",
            )
        )


def _check_mounts(info: dict[str, Any], findings: list[Finding]) -> None:
    for source, read_only in _collect_mounts(info):
        match = sensitive_mount(source)
        if match is None:
            continue
        label, description, severity = match
        if read_only and not label.endswith("docker.sock"):
            severity = _downgrade(severity)
        access = "read-only" if read_only else "read-write"
        control = "CIS Docker Benchmark 5.31" if label.endswith("docker.sock") else "CIS Docker Benchmark 5.5"
        findings.append(
            Finding(
                severity,
                f"Sensitive bind mount of {label} ({access}).",
                f"The container can reach {description}; the mount is {access}.",
                control,
            )
        )


def _check_ports(
    host: dict[str, Any], network: dict[str, Any], findings: list[Finding]
) -> None:
    ports = _object(network, "Ports")
    if not ports:
        ports = _object(host, "PortBindings")
    exposed: list[str] = []
    for container_port, bindings in ports.items():
        if not bindings:
            continue
        if not isinstance(bindings, list) or not all(isinstance(item, dict) for item in bindings):
            raise ValueError("Port bindings must be a list of objects")
        for binding in bindings:
            host_ip = str(binding.get("HostIp") or "")
            host_port = str(binding.get("HostPort") or "")
            if host_ip in ("0.0.0.0", "::", ""):
                exposed.append(f"{host_ip or '0.0.0.0'}:{host_port}->{container_port}")
    if exposed:
        findings.append(
            Finding(
                "MEDIUM",
                "Published on all interfaces: " + ", ".join(sorted(exposed)) + ".",
                "These port mappings are bound to 0.0.0.0 (or ::), so they are reachable from every network the host is on, not only from loopback.",
                None,
            )
        )


def _image_tag(image: str) -> str | None:
    """Return the tag of an image reference, or None when it has none."""

    last_slash = image.rfind("/")
    last_colon = image.rfind(":")
    if last_colon <= last_slash:
        return None
    return image[last_colon + 1 :]


def _check_image(config: dict[str, Any], findings: list[Finding]) -> None:
    image = config.get("Image")
    if not isinstance(image, str) or not image:
        return
    if "@" in image:
        return
    tag = _image_tag(image)
    if tag is None:
        findings.append(
            Finding(
                "LOW",
                f'Image "{image}" has no tag.',
                "The image reference does not pin a version, so the tag defaults to latest and the image can change between runs.",
                None,
            )
        )
    elif tag == "latest":
        findings.append(
            Finding(
                "LOW",
                f'Image "{image}" uses the latest tag.',
                "The latest tag is movable, so the image can change between runs; pin a version or a digest for reproducibility.",
                None,
            )
        )


def _check_healthcheck(config: dict[str, Any], findings: list[Finding]) -> None:
    healthcheck = config.get("Healthcheck")
    if healthcheck is None:
        findings.append(
            Finding(
                "LOW",
                "Config.Healthcheck is absent.",
                "No health check is defined, so Docker cannot tell a running container from a healthy one.",
                "CIS Docker Benchmark 5.26",
            )
        )
        return
    if not isinstance(healthcheck, dict):
        raise ValueError("Config.Healthcheck must be a JSON object")
    test = healthcheck.get("Test")
    if isinstance(test, list) and test and str(test[0]).upper() == "NONE":
        findings.append(
            Finding(
                "LOW",
                "Config.Healthcheck is disabled (Test NONE).",
                "The health check is explicitly disabled.",
                "CIS Docker Benchmark 5.26",
            )
        )


def _check_restart_policy(host: dict[str, Any], findings: list[Finding]) -> None:
    policy = host.get("RestartPolicy")
    if policy is None:
        findings.append(
            Finding(
                "LOW",
                "HostConfig.RestartPolicy is absent.",
                "No restart policy is set, so behaviour after a crash or host reboot depends on Docker's defaults.",
                None,
            )
        )
        return
    if not isinstance(policy, dict):
        raise ValueError("HostConfig.RestartPolicy must be a JSON object")
    if policy.get("Name") == "always":
        findings.append(
            Finding(
                "LOW",
                'HostConfig.RestartPolicy is "always".',
                "The container is restarted unconditionally, including after a host reboot, which can keep a misbehaving container running.",
                None,
            )
        )


def _check_limits(host: dict[str, Any], findings: list[Finding]) -> None:
    if not _positive(host.get("Memory")):
        findings.append(
            Finding(
                "LOW",
                "HostConfig.Memory is not set.",
                "No memory limit is configured, so the container can consume all host memory and affect other workloads.",
                "CIS Docker Benchmark 5.11",
            )
        )
    if not (_positive(host.get("NanoCpus")) or _positive(host.get("CpuQuota"))):
        findings.append(
            Finding(
                "LOW",
                "No CPU quota is set.",
                "NanoCpus and CpuQuota are both unset, so the container has no CPU ceiling.",
                "CIS Docker Benchmark 5.12",
            )
        )


def _check_secrets(config: dict[str, Any], findings: list[Finding]) -> None:
    env = _list(config, "Env")
    if not all(isinstance(item, str) for item in env):
        raise ValueError("Config.Env must be a list of strings")
    names: list[str] = []
    for entry in env:
        name, separator, value = entry.partition("=")
        if not separator or not value:
            continue
        tokens = set(re.split(r"[^A-Za-z0-9]+", name.upper()))
        if tokens & set(SECRET_NAME_TOKENS):
            names.append(name)
    if names:
        findings.append(
            Finding(
                "MEDIUM",
                "Secret-looking environment variables hold values: " + ", ".join(sorted(names)) + ".",
                "Environment values are stored in the container configuration and are readable by anyone who can run docker inspect; use Docker secrets or an external store instead.",
                None,
            )
        )


def _check_logging(host: dict[str, Any], findings: list[Finding]) -> None:
    log_config = host.get("LogConfig")
    if log_config is None:
        driver, options = "", {}
    else:
        if not isinstance(log_config, dict):
            raise ValueError("HostConfig.LogConfig must be a JSON object")
        driver = str(log_config.get("Type") or "")
        raw_options = log_config.get("Config")
        if raw_options is not None and not isinstance(raw_options, dict):
            raise ValueError("HostConfig.LogConfig.Config must be a JSON object")
        options = raw_options or {}

    if driver in EXTERNAL_LOG_DRIVERS:
        findings.append(
            Finding(
                "LOW",
                f'Log driver is "{driver}".',
                "This log driver sends records to the host or a remote system rather than keeping them only on the container's own disk.",
                None,
            )
        )
    if driver in ("", "json-file", "local") and not ({"max-size", "max-file"} & set(options)):
        findings.append(
            Finding(
                "LOW",
                "Log driver has no size limit.",
                "No max-size or max-file is set, so container logs grow without bound on the host disk.",
                None,
            )
        )


def audit_container(info: dict[str, Any]) -> list[Finding]:
    """Return explainable findings for one container's configuration."""

    if not isinstance(info, dict):
        raise ValueError("Each container must be a JSON object")
    host = _object(info, "HostConfig")
    network = _object(info, "NetworkSettings")
    config = _object(info, "Config")

    findings: list[Finding] = []
    _check_privileged(host, findings)
    _check_namespaces(host, findings)
    _check_capabilities(host, findings)
    _check_root_filesystem(host, findings)
    _check_security_profiles(host, findings)
    _check_user(config, findings)
    _check_mounts(info, findings)
    _check_ports(host, network, findings)
    _check_image(config, findings)
    _check_healthcheck(config, findings)
    _check_restart_policy(host, findings)
    _check_limits(host, findings)
    _check_secrets(config, findings)
    _check_logging(host, findings)
    return findings


def load_json(path: Path) -> list[dict[str, Any]]:
    """Load every container from Docker's list or a single inspect object."""

    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except RecursionError as exc:
        # A deeply nested document must fail with a message, not a traceback.
        raise ValueError("JSON is nested too deeply") from exc
    if isinstance(data, dict):
        return [data]
    if not isinstance(data, list) or not data or not all(isinstance(item, dict) for item in data):
        raise ValueError("Expected an inspect object or a nonempty list of objects.")
    return data


def _summarise(reports: list[tuple[dict[str, Any], list[Finding]]]) -> dict[str, int]:
    summary = {severity: 0 for severity in SEVERITIES}
    for _, findings in reports:
        for finding in findings:
            summary[finding.severity] += 1
    return summary


def _print_text(reports: list[tuple[dict[str, Any], list[Finding]]], summary: dict[str, int]) -> None:
    for index, (info, findings) in enumerate(reports, 1):
        print(f"\nContainer: {info.get('Name') or info.get('Id') or index}")
        if not findings:
            print("No configured checks were triggered.")
        for finding in findings:
            print(f"[{finding.severity}] {finding.evidence}")
            print(f"    {finding.explanation}")
            if finding.control:
                print(f"    Control: {finding.control}")
    print("\nSummary: " + ", ".join(f"{severity} {summary[severity]}" for severity in SEVERITIES))


def _print_json(reports: list[tuple[dict[str, Any], list[Finding]]], summary: dict[str, int]) -> None:
    document = {
        "containers": [
            {
                "name": info.get("Name") or info.get("Id") or index,
                "findings": [
                    {
                        "severity": finding.severity,
                        "evidence": finding.evidence,
                        "explanation": finding.explanation,
                        "control": finding.control,
                    }
                    for finding in findings
                ],
            }
            for index, (info, findings) in enumerate(reports, 1)
        ],
        "summary": summary,
    }
    print(json.dumps(document, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Review saved Docker inspect JSON for common risks.")
    parser.add_argument("inspect_json", type=Path, nargs="+", help="one or more files of docker inspect JSON")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument(
        "--fail-on",
        choices=["high", "medium", "low", "none"],
        default="high",
        help="lowest severity that produces a non-zero exit code (default: high)",
    )
    args = parser.parse_args()

    try:
        # Validate every file and container before displaying a partial report.
        reports: list[tuple[dict[str, Any], list[Finding]]] = []
        for path in args.inspect_json:
            for info in load_json(path):
                reports.append((info, audit_container(info)))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Could not review inspect data: {exc}") from exc

    summary = _summarise(reports)
    if args.json:
        _print_json(reports, summary)
    else:
        _print_text(reports, summary)

    threshold = {"high": 3, "medium": 2, "low": 1, "none": 0}[args.fail_on]
    worst = max((SEVERITY_RANK[finding.severity] for _, findings in reports for finding in findings), default=0)
    if threshold and worst >= threshold:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
