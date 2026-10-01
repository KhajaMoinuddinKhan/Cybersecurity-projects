"""Review a supplied JSON cloud inventory."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

# Tags checked by this example inventory.
REQUIRED_TAGS = ("Owner", "Environment")

def review_assets(
    assets: list[dict[str, Any]],
) -> list[tuple[str, str, str]]:
    """Check assets for public exposure and missing metadata."""

    findings: list[tuple[str, str, str]] = []

    for asset in assets:
        name = str(asset.get("name") or "unnamed")
        resource_type = str(asset.get("type") or "unknown")

        if "public" in asset and not isinstance(asset["public"], bool):
            findings.append(("LOW", name, "Public exposure must be recorded as a JSON boolean."))

        # Public assets get a review item, not an automatic failure.
        if asset.get("public") is True:
            findings.append(
                ("MEDIUM", name, f"{resource_type} is marked public.")
            )

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
            if not isinstance(tags.get(tag), str) or not tags[tag].strip()
        ]
        if missing:
            findings.append(
                ("LOW", name, "Missing metadata: " + ", ".join(missing))
            )

        region = asset.get("region")
        if not region or (isinstance(region, str) and not region.strip()):
            findings.append(("LOW", name, "Region is not recorded."))

    return findings

def load_assets(path: Path) -> list[dict[str, Any]]:
    """Load the asset JSON file."""

    data = json.loads(path.read_text(encoding="utf-8-sig"))

    if not isinstance(data, dict) or not isinstance(data.get("assets"), list):
        raise ValueError("Expected JSON object with an assets list.")

    if not all(isinstance(asset, dict) for asset in data["assets"]):
        raise ValueError("Every asset must be a JSON object.")

    return data["assets"]

def main() -> None:
    """Load the inventory and print the findings."""

    parser = argparse.ArgumentParser(
        description="Review a JSON cloud asset export for exposure and metadata gaps."
    )
    parser.add_argument("file", type=Path)
    args = parser.parse_args()

    if not args.file.is_file():
        raise SystemExit(f"File not found: {args.file}")

    try:
        assets = load_assets(args.file)
    except (OSError, ValueError) as exc:
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
