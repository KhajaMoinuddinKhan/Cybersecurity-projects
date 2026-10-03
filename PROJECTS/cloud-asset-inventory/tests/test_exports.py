"""Multiple inputs, per-file reporting, JSON mode and file exports."""
import csv
import json
import subprocess
import sys
from pathlib import Path

from src.inventory import (
    AWS_CONFIG,
    AZURE_RESOURCE_GRAPH,
    GCP_ASSET_INVENTORY,
    build_report,
    group_counts,
    write_findings_csv,
    write_findings_json,
    write_inventory_csv,
    write_inventory_json,
)

PROJECT_DIR = Path(__file__).resolve().parents[1]
SAMPLE_EXPORTS = PROJECT_DIR / "sample_exports"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "src.inventory", *args],
        cwd=PROJECT_DIR, capture_output=True, text=True,
    )


def test_directory_and_file_are_read_in_one_run():
    report = build_report([SAMPLE_EXPORTS, PROJECT_DIR / "sample_assets.json"])
    formats = {entry.format for entry in report.files}
    assert {AWS_CONFIG, AZURE_RESOURCE_GRAPH, GCP_ASSET_INVENTORY} <= formats
    assert all(entry.error is None for entry in report.files)
    assert len(report.assets) == 11


def test_per_file_report_names_each_file_and_its_format():
    report = build_report([SAMPLE_EXPORTS])
    by_name = {Path(entry.path).name: entry for entry in report.files}
    assert by_name["aws_config_resources.json"].format == AWS_CONFIG
    assert by_name["azure_resource_graph.json"].format == AZURE_RESOURCE_GRAPH
    assert by_name["gcp_assets.json"].format == GCP_ASSET_INVENTORY


def test_a_broken_file_is_reported_without_stopping_the_run(tmp_path):
    good = SAMPLE_EXPORTS / "gcp_assets.json"
    bad = tmp_path / "broken.json"
    bad.write_text("{not json", encoding="utf-8")
    report = build_report([bad, good])
    errors = [entry for entry in report.files if entry.error]
    assert len(errors) == 1
    assert "not valid JSON" in errors[0].error
    assert report.assets  # the good file still contributed


def test_missing_path_is_reported(tmp_path):
    report = build_report([tmp_path / "nope.json"])
    assert report.files[0].error == "Path does not exist."


def test_json_mode_emits_one_document():
    result = run_cli(str(SAMPLE_EXPORTS / "aws_config_resources.json"), "--json")
    assert result.returncode == 0
    document = json.loads(result.stdout)
    assert set(document) == {"files", "assets", "counts", "findings"}
    assert document["counts"]["by_provider"] == {"AWS": 3}


def test_human_output_shows_table_and_grouped_counts():
    result = run_cli(str(SAMPLE_EXPORTS))
    assert result.returncode == 0
    assert "Per-file report:" in result.stdout
    assert "PROVIDER" in result.stdout
    assert "Counts by provider:" in result.stdout
    assert "Counts by type:" in result.stdout
    assert "Findings:" in result.stdout


def test_export_writers_round_trip(tmp_path):
    report = build_report([SAMPLE_EXPORTS])
    inv_json = tmp_path / "inventory.json"
    inv_csv = tmp_path / "inventory.csv"
    fin_json = tmp_path / "findings.json"
    fin_csv = tmp_path / "findings.csv"

    write_inventory_json(inv_json, report.assets)
    write_inventory_csv(inv_csv, report.assets)
    write_findings_json(fin_json, report.findings)
    write_findings_csv(fin_csv, report.findings)

    assert len(json.loads(inv_json.read_text(encoding="utf-8"))) == len(report.assets)
    assert len(json.loads(fin_json.read_text(encoding="utf-8"))) == len(report.findings)

    with inv_csv.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == len(report.assets)
    assert json.loads(rows[0]["tags"]) == report.assets[0].tags

    with fin_csv.open(encoding="utf-8", newline="") as handle:
        finding_rows = list(csv.DictReader(handle))
    assert len(finding_rows) == len(report.findings)


def test_cli_writes_export_files(tmp_path):
    result = run_cli(
        str(SAMPLE_EXPORTS),
        "--inventory-json", str(tmp_path / "i.json"),
        "--inventory-csv", str(tmp_path / "i.csv"),
        "--findings-json", str(tmp_path / "f.json"),
        "--findings-csv", str(tmp_path / "f.csv"),
    )
    assert result.returncode == 0
    for name in ("i.json", "i.csv", "f.json", "f.csv"):
        assert (tmp_path / name).is_file()
