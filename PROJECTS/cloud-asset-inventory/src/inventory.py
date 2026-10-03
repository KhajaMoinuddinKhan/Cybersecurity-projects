"""Normalise cloud asset exports and report governance findings."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

# Tag names the review expects. Matching is case-insensitive so that
# providers which use lower-case labels (GCP) are still recognised.
REQUIRED_TAGS = ("Owner", "Environment")

# Resource-type fragments treated as storage by the encryption finding.
STORAGE_MARKERS = (
    "storage", "bucket", "blob", "disk", "volume", "filesystem", "filestore",
)

# Export shapes recognised by structural auto-detection.
AWS_CONFIG = "aws-config"
AZURE_RESOURCE_GRAPH = "azure-resource-graph"
GCP_ASSET_INVENTORY = "gcp-asset-inventory"
GENERIC = "generic"
FORMATS = (AWS_CONFIG, AZURE_RESOURCE_GRAPH, GCP_ASSET_INVENTORY, GENERIC)

# Top-level keys that can hold an AWS Config style resource list.
AWS_LIST_KEYS = (
    "resourceIdentifiers", "results", "Results",
    "configurationItems", "ConfigurationItems",
)

# A region that was present but recorded in the wrong shape.
REGION_TYPE_PROBLEM = "Region must be recorded as text."

# Severity labels used by the finding pass.
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

# Columns written by the CSV exports.
INVENTORY_COLUMNS = (
    "provider", "resource_type", "identifier", "name",
    "region", "public", "encrypted", "source", "tags",
)
FINDING_COLUMNS = ("severity", "category", "asset", "provider", "message")


@dataclass
class Asset:
    """One cloud resource normalised into a single shape."""

    provider: str
    resource_type: str
    identifier: str
    name: str
    region: str | None
    tags: dict[str, Any]
    public: bool | None
    encrypted: bool | None
    source: str
    problems: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return the record as a JSON-serialisable mapping."""

        return {
            "provider": self.provider,
            "resource_type": self.resource_type,
            "identifier": self.identifier,
            "name": self.name,
            "region": self.region,
            "tags": self.tags,
            "public": self.public,
            "encrypted": self.encrypted,
            "source": self.source,
        }


@dataclass
class Finding:
    """One review item, tied back to the asset it belongs to."""

    severity: str
    category: str
    asset: str
    provider: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Return the finding as a JSON-serialisable mapping."""

        return {
            "severity": self.severity,
            "category": self.category,
            "asset": self.asset,
            "provider": self.provider,
            "message": self.message,
        }


@dataclass
class FileReport:
    """What one input file contributed to the run."""

    path: str
    format: str | None
    assets: int
    skipped: int
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the file report as a JSON-serialisable mapping."""

        return {
            "path": self.path,
            "format": self.format,
            "assets": self.assets,
            "skipped": self.skipped,
            "error": self.error,
        }


@dataclass
class Report:
    """The full result of one run: files, assets and findings."""

    files: list[FileReport]
    assets: list[Asset]
    findings: list[Finding]


def _text(value: Any) -> str | None:
    """Return stripped text, or None when the value is not usable text."""

    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _coerce_region(value: Any, problems: list[str]) -> str | None:
    """Return a usable region, recording a problem for the wrong type."""

    if value is None:
        return None
    if isinstance(value, str):
        return value.strip() or None
    problems.append(REGION_TYPE_PROBLEM)
    return None


def _coerce_tags(value: Any, problems: list[str]) -> dict[str, Any]:
    """Return the tag mapping, recording a problem for the wrong type."""

    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    problems.append("Tags are not stored as a JSON object.")
    return {}


def _coerce_bool(value: Any, problems: list[str], label: str) -> bool | None:
    """Return a boolean, recording a problem when it is not one."""

    if value is None:
        return None
    if isinstance(value, bool):
        return value
    problems.append(f"{label} must be recorded as a JSON boolean.")
    return None


def _find_bool(mapping: Any, keys: tuple[str, ...]) -> bool | None:
    """Return the first boolean under any of the given keys, else None."""

    if not isinstance(mapping, dict):
        return None
    for key in keys:
        if isinstance(mapping.get(key), bool):
            return mapping[key]
    return None


def _bool_field(
    item: dict[str, Any],
    direct_keys: tuple[str, ...],
    nested: Any,
    nested_keys: tuple[str, ...],
    problems: list[str],
    label: str,
) -> bool | None:
    """Read a boolean from a direct field, falling back to a nested block."""

    for key in direct_keys:
        if key in item:
            return _coerce_bool(item[key], problems, label)
    return _find_bool(nested, nested_keys)


def _tag_present(tags: dict[str, Any], name: str) -> bool:
    """Return True when a non-empty tag matching name exists."""

    wanted = name.lower()
    for key, value in tags.items():
        if isinstance(key, str) and key.lower() == wanted:
            return isinstance(value, str) and bool(value.strip())
    return False


def _is_storage(resource_type: str) -> bool:
    """Return True when a resource type looks like a storage service."""

    lowered = resource_type.lower()
    return any(marker in lowered for marker in STORAGE_MARKERS)


def _adapt_items(
    items: Any,
    source: str,
    mapper: Callable[[dict[str, Any], str], Asset | None],
) -> tuple[list[Asset], int]:
    """Map a list of raw records, counting the ones that cannot be mapped."""

    assets: list[Asset] = []
    skipped = 0
    for item in items:
        if not isinstance(item, dict):
            skipped += 1
            continue
        asset = mapper(item, source)
        if asset is None:
            skipped += 1
            continue
        assets.append(asset)
    return assets, skipped


def _map_generic(item: dict[str, Any], source: str) -> Asset | None:
    """Map the tool's own generic asset record."""

    problems: list[str] = []
    provider = _text(item.get("provider")) or "cloud"
    resource_type = _text(item.get("type")) or "unknown"
    identifier = (
        _text(item.get("identifier")) or _text(item.get("id")) or _text(item.get("name"))
    )
    name = _text(item.get("name")) or identifier or "unnamed"
    region = _coerce_region(item.get("region"), problems)
    tags = _coerce_tags(item.get("tags"), problems)
    public = _coerce_bool(item.get("public"), problems, "Public exposure")
    encrypted = _coerce_bool(item.get("encrypted"), problems, "Encryption state")
    return Asset(
        provider, resource_type, identifier or name, name,
        region, tags, public, encrypted, source, tuple(problems),
    )


def adapt_generic(data: dict[str, Any], source: str) -> tuple[list[Asset], int]:
    """Adapt the tool's own generic assets list."""

    return _adapt_items(data.get("assets", []), source, _map_generic)


def _map_aws(item: dict[str, Any], source: str) -> Asset | None:
    """Map one AWS Config resource record."""

    problems: list[str] = []
    resource_type = _text(item.get("resourceType"))
    identifier = _text(item.get("resourceId")) or _text(item.get("resourceName"))
    if resource_type is None or identifier is None:
        return None
    name = _text(item.get("resourceName")) or identifier
    region = _coerce_region(item.get("awsRegion") or item.get("region"), problems)
    tags = _coerce_tags(item.get("tags"), problems)
    configuration = item.get("configuration") if isinstance(item.get("configuration"), dict) else {}
    public = _bool_field(
        item, ("public", "isPublic"), configuration,
        ("public", "isPublic", "PubliclyAccessible"), problems, "Public exposure",
    )
    encrypted = _bool_field(
        item, ("encrypted", "isEncrypted"), configuration,
        ("encrypted", "isEncrypted", "Encrypted", "StorageEncrypted"), problems,
        "Encryption state",
    )
    return Asset(
        "AWS", resource_type, identifier, name,
        region, tags, public, encrypted, source, tuple(problems),
    )


def adapt_aws_config(data: dict[str, Any], source: str) -> tuple[list[Asset], int]:
    """Adapt an AWS Config style resource list."""

    items: Any = []
    for key in AWS_LIST_KEYS:
        if isinstance(data.get(key), list):
            items = data[key]
            break
    return _adapt_items(items, source, _map_aws)


def _azure_public(
    item: dict[str, Any], properties: dict[str, Any], problems: list[str]
) -> bool | None:
    """Derive the exposure flag from an Azure resource record."""

    for key in ("public", "isPublic"):
        if key in item:
            return _coerce_bool(item[key], problems, "Public exposure")
    for key in ("public", "isPublic"):
        if key in properties:
            return _coerce_bool(properties[key], problems, "Public exposure")
    access = properties.get("publicNetworkAccess") or properties.get("publicAccess")
    if isinstance(access, str):
        lowered = access.strip().lower()
        if lowered in ("enabled", "true"):
            return True
        if lowered in ("disabled", "false"):
            return False
    allow_blob = properties.get("allowBlobPublicAccess")
    if isinstance(allow_blob, bool):
        return allow_blob
    return None


def _azure_encrypted(
    item: dict[str, Any], properties: dict[str, Any], problems: list[str]
) -> bool | None:
    """Derive the encryption state from an Azure resource record."""

    for key in ("encrypted", "isEncrypted"):
        if key in item:
            return _coerce_bool(item[key], problems, "Encryption state")
    for key in ("encrypted", "encryptionEnabled"):
        if key in properties:
            return _coerce_bool(properties[key], problems, "Encryption state")
    if isinstance(properties.get("encryption"), dict):
        # An encryption block is present, so encryption is configured.
        return True
    return None


def _map_azure(item: dict[str, Any], source: str) -> Asset | None:
    """Map one Azure Resource Graph resource record."""

    problems: list[str] = []
    resource_type = _text(item.get("type"))
    identifier = _text(item.get("id")) or _text(item.get("name"))
    if resource_type is None or identifier is None:
        return None
    name = _text(item.get("name")) or identifier.rsplit("/", 1)[-1]
    region = _coerce_region(item.get("location"), problems)
    tags = _coerce_tags(item.get("tags"), problems)
    properties = item.get("properties") if isinstance(item.get("properties"), dict) else {}
    public = _azure_public(item, properties, problems)
    encrypted = _azure_encrypted(item, properties, problems)
    return Asset(
        "Azure", resource_type, identifier, name,
        region, tags, public, encrypted, source, tuple(problems),
    )


def adapt_azure_resource_graph(data: dict[str, Any], source: str) -> tuple[list[Asset], int]:
    """Adapt an Azure Resource Graph style value array."""

    return _adapt_items(data.get("value", []), source, _map_azure)


def _gcp_iam_is_public(policy: Any) -> bool:
    """Return True when an IAM policy grants access to all users."""

    if not isinstance(policy, dict):
        return False
    bindings = policy.get("bindings")
    if not isinstance(bindings, list):
        return False
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        members = binding.get("members")
        if isinstance(members, list) and any(
            member in ("allUsers", "allAuthenticatedUsers") for member in members
        ):
            return True
    return False


def _gcp_public(
    item: dict[str, Any], resource: dict[str, Any], problems: list[str]
) -> bool | None:
    """Derive the exposure flag from a GCP asset record."""

    data = resource.get("data") if isinstance(resource.get("data"), dict) else {}
    for mapping in (item, resource, data):
        for key in ("public", "isPublic"):
            if key in mapping:
                return _coerce_bool(mapping[key], problems, "Public exposure")
    if _gcp_iam_is_public(item.get("iamPolicy")):
        return True
    return None


def _gcp_encrypted(
    item: dict[str, Any], resource: dict[str, Any], problems: list[str]
) -> bool | None:
    """Derive the encryption state from a GCP asset record."""

    for mapping in (item, resource):
        for key in ("encrypted", "isEncrypted"):
            if key in mapping:
                return _coerce_bool(mapping[key], problems, "Encryption state")
    data = resource.get("data") if isinstance(resource.get("data"), dict) else {}
    for key in ("encrypted", "isEncrypted"):
        if key in data:
            return _coerce_bool(data[key], problems, "Encryption state")
    if isinstance(data.get("encryption"), dict):
        # A default encryption block is present, so encryption is configured.
        return True
    return None


def _map_gcp(item: dict[str, Any], source: str) -> Asset | None:
    """Map one GCP Cloud Asset Inventory record."""

    problems: list[str] = []
    resource_type = _text(item.get("assetType"))
    identifier = _text(item.get("name"))
    if resource_type is None or identifier is None:
        return None
    name = identifier.rsplit("/", 1)[-1] or identifier
    resource = item.get("resource") if isinstance(item.get("resource"), dict) else {}
    region = _coerce_region(resource.get("location") or item.get("location"), problems)
    raw_tags = (
        resource.get("labels") or resource.get("tags")
        or item.get("labels") or item.get("tags")
    )
    tags = _coerce_tags(raw_tags, problems)
    public = _gcp_public(item, resource, problems)
    encrypted = _gcp_encrypted(item, resource, problems)
    return Asset(
        "GCP", resource_type, identifier, name,
        region, tags, public, encrypted, source, tuple(problems),
    )


def adapt_gcp_assets(data: dict[str, Any], source: str) -> tuple[list[Asset], int]:
    """Adapt a GCP asset inventory style assets array."""

    return _adapt_items(data.get("assets", []), source, _map_gcp)


ADAPTERS: dict[str, Callable[[dict[str, Any], str], tuple[list[Asset], int]]] = {
    AWS_CONFIG: adapt_aws_config,
    AZURE_RESOURCE_GRAPH: adapt_azure_resource_graph,
    GCP_ASSET_INVENTORY: adapt_gcp_assets,
    GENERIC: adapt_generic,
}


def detect_format(data: Any) -> str:
    """Return the export format implied by the document structure."""

    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object at the top level.")

    if isinstance(data.get("value"), list):
        return AZURE_RESOURCE_GRAPH

    for key in AWS_LIST_KEYS:
        if isinstance(data.get(key), list):
            return AWS_CONFIG

    if isinstance(data.get("assets"), list):
        items = data["assets"]
        if any(isinstance(item, dict) and "assetType" in item for item in items):
            return GCP_ASSET_INVENTORY
        if any(isinstance(item, dict) and "provider" in item for item in items):
            return GENERIC
        if any(
            isinstance(item, dict) and "type" in item and "name" in item
            for item in items
        ):
            return GENERIC
        # An empty or unrecognised assets list defaults to the generic shape.
        return GENERIC

    raise ValueError(
        "Unrecognised export format: expected an AWS Config resource list, an "
        "Azure Resource Graph value array, a GCP asset inventory assets array, "
        "or a generic assets list."
    )


def parse_document(data: Any, source: str) -> tuple[str, list[Asset], int]:
    """Detect the format and normalise the document's assets."""

    fmt = detect_format(data)
    assets, skipped = ADAPTERS[fmt](data, source)
    return fmt, assets, skipped


def load_export(path: Path) -> tuple[str, list[Asset], int]:
    """Read one export file and normalise its assets."""

    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path.name} is not valid UTF-8 text: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"{path.name} could not be read: {exc}") from exc

    try:
        data = json.loads(text)
    except RecursionError as exc:
        # A deeply nested document must fail with a message, not a traceback.
        raise ValueError(f"{path.name} is nested too deeply to parse") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name} is not valid JSON: {exc}") from exc

    return parse_document(data, path.name)


def _iter_targets(paths: list[Path]) -> Iterator[tuple[Path, str | None]]:
    """Yield each input file in order, with an error for unusable paths."""

    for path in paths:
        if path.is_dir():
            found = sorted(child for child in path.glob("*.json") if child.is_file())
            if not found:
                yield path, "No .json exports found in directory."
            for child in found:
                yield child, None
        elif path.is_file():
            yield path, None
        else:
            yield path, "Path does not exist."


def collect_inputs(paths: list[Path]) -> list[Path]:
    """Expand files and directories into the list of export files to read."""

    return [path for path, error in _iter_targets(paths) if error is None]


def build_findings(assets: list[Asset]) -> list[Finding]:
    """Apply the configured rules to the normalised assets."""

    findings: list[Finding] = []

    for asset in assets:
        label = asset.name or asset.identifier or "unnamed"

        # Values that were present but recorded in the wrong shape.
        for problem in asset.problems:
            findings.append(
                Finding(LOW, "DATA_QUALITY", label, asset.provider, problem)
            )

        # Public assets get a review item, not an automatic failure.
        if asset.public is True:
            findings.append(
                Finding(
                    MEDIUM, "PUBLIC_EXPOSURE", label, asset.provider,
                    f"{asset.resource_type} is marked publicly exposed.",
                )
            )

        if not asset.tags:
            findings.append(
                Finding(LOW, "MISSING_TAGS", label, asset.provider, "No tags are recorded.")
            )

        missing = [tag for tag in REQUIRED_TAGS if not _tag_present(asset.tags, tag)]
        if missing:
            findings.append(
                Finding(
                    LOW, "MISSING_OWNER_ENV", label, asset.provider,
                    "Missing metadata: " + ", ".join(missing),
                )
            )

        if asset.region is None and REGION_TYPE_PROBLEM not in asset.problems:
            findings.append(
                Finding(LOW, "MISSING_REGION", label, asset.provider, "Region is not recorded.")
            )

        if asset.encrypted is False and _is_storage(asset.resource_type):
            findings.append(
                Finding(
                    MEDIUM, "UNENCRYPTED_STORAGE", label, asset.provider,
                    f"{asset.resource_type} records encryption as disabled.",
                )
            )

    return findings


def _load_report(path: Path, assets: list[Asset]) -> FileReport:
    """Load one file, appending its assets and describing the outcome."""

    try:
        fmt, parsed, skipped = load_export(path)
    except ValueError as exc:
        return FileReport(str(path), None, 0, 0, error=str(exc))
    assets.extend(parsed)
    return FileReport(str(path), fmt, len(parsed), skipped)


def build_report(paths: list[Path]) -> Report:
    """Read every input and build the combined report."""

    reports: list[FileReport] = []
    assets: list[Asset] = []

    for path, error in _iter_targets(paths):
        if error is not None:
            reports.append(FileReport(str(path), None, 0, 0, error=error))
        else:
            reports.append(_load_report(path, assets))

    # A stable order keeps the table and the findings reproducible.
    assets.sort(
        key=lambda asset: (
            asset.provider.lower(),
            asset.resource_type.lower(),
            asset.name.lower(),
            asset.identifier,
        )
    )
    return Report(reports, assets, build_findings(assets))


def group_counts(assets: list[Asset]) -> dict[str, dict[str, int]]:
    """Count the assets grouped by provider and by resource type."""

    by_provider = Counter(asset.provider for asset in assets)
    by_type = Counter(asset.resource_type for asset in assets)
    return {
        "by_provider": {name: by_provider[name] for name in sorted(by_provider)},
        "by_type": {name: by_type[name] for name in sorted(by_type)},
    }


def render_table(assets: list[Asset]) -> str:
    """Render the assets as a fixed-width table."""

    header = ("PROVIDER", "TYPE", "NAME", "REGION")
    rows = [
        (asset.provider, asset.resource_type, asset.name, asset.region or "-")
        for asset in assets
    ]
    widths = [
        max([len(header[index])] + [len(row[index]) for row in rows])
        for index in range(len(header))
    ]

    def line(cells: tuple[str, ...]) -> str:
        return "  ".join(cells[index].ljust(widths[index]) for index in range(len(header))).rstrip()

    lines = [line(header), "  ".join("-" * width for width in widths)]
    lines.extend(line(row) for row in rows)
    return "\n".join(lines)


def report_to_dict(report: Report) -> dict[str, Any]:
    """Return the whole report as a JSON-serialisable mapping."""

    return {
        "files": [entry.to_dict() for entry in report.files],
        "assets": [asset.to_dict() for asset in report.assets],
        "counts": group_counts(report.assets),
        "findings": [finding.to_dict() for finding in report.findings],
    }


def render_text(report: Report) -> str:
    """Render the report for a person reading the terminal."""

    lines = ["Per-file report:"]
    for entry in report.files:
        if entry.error is not None:
            lines.append(f"  {entry.path}: ERROR - {entry.error}")
        else:
            detail = f"parsed {entry.assets} asset(s) as {entry.format}"
            if entry.skipped:
                detail += f", skipped {entry.skipped} record(s)"
            lines.append(f"  {entry.path}: {detail}")

    lines.append("")
    lines.append(f"Assets found: {len(report.assets)}")
    if report.assets:
        lines.append(render_table(report.assets))

    counts = group_counts(report.assets)
    lines.append("")
    lines.append("Counts by provider:")
    for name, total in counts["by_provider"].items():
        lines.append(f"  {name}: {total}")
    lines.append("Counts by type:")
    for name, total in counts["by_type"].items():
        lines.append(f"  {name}: {total}")

    lines.append("")
    lines.append(f"Findings: {len(report.findings)}")
    if not report.findings:
        lines.append("No configured checks were triggered.")
    for finding in report.findings:
        lines.append(f"[{finding.severity}] {finding.category} {finding.asset}: {finding.message}")

    return "\n".join(lines)


def _ensure_parent(path: Path) -> None:
    """Create the export's parent directory when it is missing."""

    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


def write_inventory_json(path: Path, assets: list[Asset]) -> None:
    """Write the normalised inventory as JSON."""

    _ensure_parent(path)
    path.write_text(
        json.dumps([asset.to_dict() for asset in assets], indent=2) + "\n",
        encoding="utf-8",
    )


def write_inventory_csv(path: Path, assets: list[Asset]) -> None:
    """Write the normalised inventory as CSV."""

    _ensure_parent(path)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=INVENTORY_COLUMNS)
        writer.writeheader()
        for asset in assets:
            row = asset.to_dict()
            row["tags"] = json.dumps(row["tags"], sort_keys=True)
            writer.writerow(row)


def write_findings_json(path: Path, findings: list[Finding]) -> None:
    """Write the findings as JSON."""

    _ensure_parent(path)
    path.write_text(
        json.dumps([finding.to_dict() for finding in findings], indent=2) + "\n",
        encoding="utf-8",
    )


def write_findings_csv(path: Path, findings: list[Finding]) -> None:
    """Write the findings as CSV."""

    _ensure_parent(path)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FINDING_COLUMNS)
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding.to_dict())


def main() -> None:
    """Read the exports and print the inventory, counts and findings."""

    parser = argparse.ArgumentParser(
        description="Normalise cloud asset exports and report governance findings."
    )
    parser.add_argument(
        "paths", nargs="+", type=Path, metavar="PATH",
        help="Export files and/or directories of .json exports.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit the whole report as a single JSON document.",
    )
    parser.add_argument("--inventory-json", type=Path, metavar="PATH",
                        help="Write the normalised inventory to a JSON file.")
    parser.add_argument("--inventory-csv", type=Path, metavar="PATH",
                        help="Write the normalised inventory to a CSV file.")
    parser.add_argument("--findings-json", type=Path, metavar="PATH",
                        help="Write the findings to a JSON file.")
    parser.add_argument("--findings-csv", type=Path, metavar="PATH",
                        help="Write the findings to a CSV file.")
    args = parser.parse_args()

    report = build_report(args.paths)

    if args.json:
        print(json.dumps(report_to_dict(report), indent=2))
    else:
        print(render_text(report))

    def emit(message: str) -> None:
        print(message, file=sys.stderr if args.json else sys.stdout)

    try:
        if args.inventory_json:
            write_inventory_json(args.inventory_json, report.assets)
            emit(f"Wrote inventory JSON: {args.inventory_json}")
        if args.inventory_csv:
            write_inventory_csv(args.inventory_csv, report.assets)
            emit(f"Wrote inventory CSV: {args.inventory_csv}")
        if args.findings_json:
            write_findings_json(args.findings_json, report.findings)
            emit(f"Wrote findings JSON: {args.findings_json}")
        if args.findings_csv:
            write_findings_csv(args.findings_csv, report.findings)
            emit(f"Wrote findings CSV: {args.findings_csv}")
    except OSError as exc:
        raise SystemExit(f"Could not write export: {exc}") from exc


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Inventory review failed: {exc}") from exc
