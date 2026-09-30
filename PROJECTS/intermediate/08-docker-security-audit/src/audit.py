"""Review saved Docker inspect data for focused security risks."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


# [SECTION] Container security checks
def audit_container(info: dict[str, Any]) -> list[tuple[str, str]]:
    """Inspect selected Docker settings and return severity-tagged findings."""

    findings: list[tuple[str, str]] = []
    host = info.get("HostConfig") or {}
    network = info.get("NetworkSettings") or {}
    config = info.get("Config") or {}

    # Privileged containers gain broad host-level capabilities and deserve review.
    if host.get("Privileged") is True:
        findings.append(("HIGH", "Container runs in privileged mode."))

    # Sharing host namespaces reduces isolation between the container and host.
    if host.get("NetworkMode") == "host":
        findings.append(("MEDIUM", "Container shares the host network namespace."))
    if host.get("PidMode") == "host":
        findings.append(("MEDIUM", "Container shares the host PID namespace."))
    if host.get("IpcMode") == "host":
        findings.append(("MEDIUM", "Container shares the host IPC namespace."))

    # Review sensitive bind mounts that expose powerful host resources.
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

    # Published ports are not automatically unsafe, but they expand reachable surface.
    ports = network.get("Ports") or {}
    if ports:
        findings.append(
            ("LOW", f"{len(ports)} published port mapping(s) require review.")
        )

    # An empty user field normally means the image's default user is used, often root.
    if not str(config.get("User") or "").strip():
        findings.append(
            ("MEDIUM", "Container does not explicitly declare a non-root user.")
        )

    return findings


# [SECTION] Docker inspect loader
def load_json(path: Path) -> dict[str, Any]:
    """Load either one inspect object or the first object from Docker's list form."""

    data = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(data, list):
        if not data or not isinstance(data[0], dict):
            raise ValueError("Expected a Docker inspect object or list.")
        return data[0]

    if not isinstance(data, dict):
        raise ValueError("Inspect data must be a JSON object.")

    return data


# [SECTION] Command-line interface
def main() -> None:
    """Load Docker inspect JSON, run checks, and print the findings."""

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
