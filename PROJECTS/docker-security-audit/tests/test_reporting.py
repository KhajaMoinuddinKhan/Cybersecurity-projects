"""The command line reports severities, a summary, JSON and an exit code."""
import json
import subprocess
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]

RISKY = {
    "Name": "/risky",
    "Config": {"User": "root", "Image": "app:latest"},
    "HostConfig": {"Privileged": True},
}

SAFE = {
    "Name": "/safe",
    "Config": {
        "User": "1000",
        "Image": "app@sha256:" + "a" * 64,
        "Env": ["APP_MODE=production"],
        "Healthcheck": {"Test": ["CMD", "true"]},
    },
    "HostConfig": {
        "Privileged": False,
        "NetworkMode": "bridge",
        "CapDrop": ["ALL"],
        "ReadonlyRootfs": True,
        "SecurityOpt": [],
        "RestartPolicy": {"Name": "on-failure"},
        "Memory": 268435456,
        "NanoCpus": 500000000,
        "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m"}},
    },
    "NetworkSettings": {"Ports": {}},
}


def run(*args):
    return subprocess.run(
        [sys.executable, "-m", "src.audit", *args],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
    )


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return str(path)


def test_high_severity_gives_a_non_zero_exit_code(tmp_path):
    path = write(tmp_path, "inspect.json", RISKY)
    result = run(path)
    assert result.returncode == 1
    assert "[HIGH]" in result.stdout


def test_fail_on_none_suppresses_the_exit_code(tmp_path):
    path = write(tmp_path, "inspect.json", RISKY)
    assert run("--fail-on", "none", path).returncode == 0


def test_summary_counts_by_severity(tmp_path):
    path = write(tmp_path, "inspect.json", RISKY)
    summary = run(path).stdout.split("Summary:", 1)[1]
    assert "HIGH" in summary and "MEDIUM" in summary and "LOW" in summary


def test_multiple_file_arguments_are_all_reviewed(tmp_path):
    one = write(tmp_path, "one.json", RISKY)
    two = write(tmp_path, "two.json", {"Name": "/second", "HostConfig": {"PidMode": "host"}})
    result = run(one, two)
    assert "/risky" in result.stdout
    assert "/second" in result.stdout


def test_single_object_and_array_are_equivalent(tmp_path):
    single = write(tmp_path, "single.json", RISKY)
    array = write(tmp_path, "array.json", [RISKY])
    a = json.loads(run("--json", single).stdout)
    b = json.loads(run("--json", array).stdout)
    assert a["containers"] == b["containers"]


def test_json_mode_returns_a_document_with_every_field(tmp_path):
    path = write(tmp_path, "inspect.json", RISKY)
    document = json.loads(run("--json", path).stdout)
    assert document["summary"]["HIGH"] >= 1
    finding = document["containers"][0]["findings"][0]
    assert set(finding) == {"severity", "evidence", "explanation", "control"}


def test_json_mode_lists_every_container(tmp_path):
    path = write(tmp_path, "inspect.json", [RISKY, SAFE])
    document = json.loads(run("--json", path).stdout)
    assert [item["name"] for item in document["containers"]] == ["/risky", "/safe"]


def test_clean_container_is_reported_without_findings(tmp_path):
    path = write(tmp_path, "inspect.json", SAFE)
    result = run(path)
    assert result.returncode == 0
    assert "No configured checks were triggered." in result.stdout
