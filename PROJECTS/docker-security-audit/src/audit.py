"""Review saved Docker inspect data without contacting the daemon."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _object(info: dict[str, Any], key: str) -> dict[str, Any]:
    value = info.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be a JSON object")
    return value


def bind_source(binding: str) -> str:
    """Return the host path of a bind spec, keeping a Windows drive letter."""

    parts = binding.split(":")
    if (
        len(parts) >= 2
        and len(parts[0]) == 1
        and parts[0].isalpha()
        and parts[1][:1] in {"\\", "/", ""}
    ):
        return f"{parts[0]}:{parts[1]}"
    return parts[0]

def is_host_root(source: str) -> bool:
    """True for a filesystem root: "/", "\\" or a bare drive such as "C:"."""

    stripped = source.rstrip("/\\")
    if not stripped:
        return True
    return len(stripped) == 2 and stripped[0].isalpha() and stripped[1] == ":"

def audit_container(info: dict[str, Any]) -> list[tuple[str, str]]:
    """Return explainable findings for one container's configuration."""
    if not isinstance(info, dict):
        raise ValueError("Each container must be a JSON object")
    findings: list[tuple[str, str]] = []
    host = _object(info, "HostConfig")
    network = _object(info, "NetworkSettings")
    config = _object(info, "Config")

    if host.get("Privileged") is True:
        findings.append(("HIGH", "Container runs in privileged mode."))
    for setting, namespace in (("NetworkMode", "network"), ("PidMode", "PID"), ("IpcMode", "IPC")):
        if host.get(setting) == "host":
            findings.append(("MEDIUM", f"Container shares the host {namespace} namespace."))

    bindings = host.get("Binds")
    if bindings is None:
        bindings = []
    if not isinstance(bindings, list) or not all(isinstance(item, str) for item in bindings):
        raise ValueError("HostConfig.Binds must be a list of strings")
    sources: set[str] = set()
    for binding in bindings:
        source = bind_source(binding)
        if not source:
            # An empty host path is not a bind and must not be read as "/".
            continue
        sources.add(source.rstrip("/\\") or "/")

    # Docker records --mount bind mounts here even when HostConfig.Binds is empty.
    mounts = info.get("Mounts")
    if mounts is None:
        mounts = []
    if not isinstance(mounts, list) or not all(isinstance(item, dict) for item in mounts):
        raise ValueError("Mounts must be a list of objects")
    for mount in mounts:
        if mount.get("Type") == "bind":
            source = mount.get("Source")
            if not isinstance(source, str) or not source:
                raise ValueError("Bind mount Source must be nonempty text")
            sources.add(source.rstrip("/") or "/")
    if any(is_host_root(source) for source in sources):
        findings.append(("HIGH", "Host root filesystem is mounted into the container."))
    if any(source.endswith("/docker.sock") for source in sources):
        findings.append(("HIGH", "Docker socket is mounted into the container."))

    ports = _object(network, "Ports")
    published_ports = sum(1 for bindings in ports.values() if bindings)
    if published_ports:
        findings.append(("LOW", f"{published_ports} published port mapping(s) require review."))

    # A numeric UID 0 is a real declaration, so only None means "not declared".
    raw_user = config.get("User")
    user = "" if raw_user is None else str(raw_user).strip().split(":", 1)[0]
    if not user:
        findings.append(("MEDIUM", "Container does not explicitly declare a non-root user."))
    elif user == "root" or (user.isdecimal() and int(user) == 0):
        findings.append(("MEDIUM", "Container explicitly runs as root (UID 0)."))
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Review saved Docker inspect JSON for common risks.")
    parser.add_argument("inspect_json", type=Path)
    args = parser.parse_args()
    try:
        containers = load_json(args.inspect_json)
        # Validate the complete file before displaying a partial report.
        reports = [(info, audit_container(info)) for info in containers]
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Could not review inspect data: {exc}") from exc
    for index, (info, findings) in enumerate(reports, 1):
        print(f"\nContainer: {info.get('Name') or info.get('Id') or index}")
        if not findings:
            print("No configured checks were triggered.")
        for severity, message in findings:
            print(f"[{severity}] {message}")


if __name__ == "__main__":
    main()
