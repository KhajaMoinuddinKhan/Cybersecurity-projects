"""Review Docker inspect data for common risky settings."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

def audit_container(info: dict[str, Any]) -> list[tuple[str, str]]:
    """Check Docker settings and return findings."""

    findings: list[tuple[str, str]] = []
    host = info.get("HostConfig") or {}
    network = info.get("NetworkSettings") or {}
    config = info.get("Config") or {}

    # Privileged mode gives the container broad host access.
    if host.get("Privileged") is True:
        findings.append(("HIGH", "Container runs in privileged mode."))

    if host.get("NetworkMode") == "host":
        findings.append(("MEDIUM", "Container shares the host network namespace."))
    if host.get("PidMode") == "host":
        findings.append(("MEDIUM", "Container shares the host PID namespace."))
    if host.get("IpcMode") == "host":
        findings.append(("MEDIUM", "Container shares the host IPC namespace."))

    # Check mounts that expose sensitive host resources.
    for binding in host.get("Binds") or []:
        source = binding.split(":", 1)[0]
        if source == "/":
            findings.append(
                ("HIGH", "Host root filesystem is mounted into the container.")
            )
        if source.endswith("/docker.sock"):
            findings.append(
                ("HIGH", "Docker socket is mounted into the container.")
            )

    ports = network.get("Ports") or {}
    published_ports = sum(1 for bindings in ports.values() if bindings)
    if published_ports:
        findings.append(
            ("LOW", f"{published_ports} published port mapping(s) require review.")
        )

    if not str(config.get("User") or "").strip():
        findings.append(
            ("MEDIUM", "Container does not explicitly declare a non-root user.")
        )

    return findings

def load_json(path: Path) -> dict[str, Any]:
    """Load Docker inspect JSON."""

    data = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(data, list):
        if not data or not isinstance(data[0], dict):
            raise ValueError("Expected a Docker inspect object or list.")
        return data[0]

    if not isinstance(data, dict):
        raise ValueError("Inspect data must be a JSON object.")

    return data

def main() -> None:
    """Load the file and print the findings."""

    parser = argparse.ArgumentParser(
        description="Audit Docker inspect JSON for common risks."
    )
    parser.add_argument("inspect_json", type=Path)
    args = parser.parse_args()

    if not args.inspect_json.is_file():
        raise SystemExit(f"File not found: {args.inspect_json}")

    try:
        findings = audit_container(load_json(args.inspect_json))
    except (ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Invalid inspect JSON: {exc}") from exc

    if not findings:
        print("No configured checks were triggered.")

    for severity, message in findings:
        print(f"[{severity}] {message}")

if __name__ == "__main__":
    main()
