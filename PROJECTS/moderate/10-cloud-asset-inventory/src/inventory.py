"""Review a synthetic cloud-asset export for simple security gaps."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


# [SECTION] Required governance metadata
REQUIRED_TAGS = ("Owner", "Environment")


# [SECTION] Asset review rules
def review_assets(
    assets: list[dict[str, Any]],
) -> list[tuple[str, str, str]]:
    """Review synthetic assets for public exposure and missing metadata."""

    findings: list[tuple[str, str, str]] = []

    for asset in assets:
        name = str(asset.get("name") or "unnamed")
        resource_type = str(asset.get("type") or "unknown")

        # Public exposure is surfaced for analyst review rather than assumed malicious.
        if asset.get("public") is True:
            findings.append(
                ("MEDIUM", name, f"{resource_type} is marked public.")
            )

        # Ownership and environment tags support accountability and asset governance.
        raw_tags = asset.get("tags")
        if raw_tags is None:
            tags: dict[str, Any] = {}
        elif isinstance(raw_tags, dict):
            tags = raw_tags
        else:
            findings.append(("LOW", name, "Tags are not stored as a JSON object."))
            tags = {}

        missing = [
            tag
            for tag in REQUIRED_TAGS
            if not tags.get(tag)
        ]
        if missing:
            findings.append(
                ("LOW", name, "Missing metadata: " + ", ".join(missing))
            )

        # Region is useful for inventory, residency, and incident-response context.
        if not asset.get("region"):
            findings.append(("LOW", name, "Region is not recorded."))

    return findings


# [SECTION] Asset-file validation
def load_assets(path: Path) -> list[dict[str, Any]]:
    """Load and validate the expected synthetic cloud inventory JSON structure."""

    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict) or not isinstance(data.get("assets"), list):
        raise ValueError("Expected JSON object with an assets list.")

    if not all(isinstance(asset, dict) for asset in data["assets"]):
        raise ValueError("Every asset must be a JSON object.")

    return data["assets"]


# [SECTION] Command-line interface
def main() -> None:
    """Load the inventory, print assets, and report configured security gaps."""

    parser = argparse.ArgumentParser(
        description="Inventory synthetic cloud assets and flag simple gaps."
    )
    parser.add_argument("file", type=Path)
    args = parser.parse_args()

    if not args.file.is_file():
        raise SystemExit(f"File not found: {args.file}")

    try:
        assets = load_assets(args.file)
    except (ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Invalid asset file: {exc}") from exc

    print(f"Assets found: {len(assets)}")
    for asset in assets:
        print(
            f"- {asset.get('provider', 'cloud')} | "
            f"{asset.get('type', 'unknown')} | "
            f"{asset.get('name', 'unnamed')}"
        )

    print("\nBasic findings:")
    findings = review_assets(assets)
    if not findings:
        print("No configured checks were triggered.")

    for severity, name, message in findings:
        print(f"[{severity}] {name}: {message}")


if __name__ == "__main__":
    main()
