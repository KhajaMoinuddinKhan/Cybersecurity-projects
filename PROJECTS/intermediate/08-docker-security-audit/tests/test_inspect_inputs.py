import json
import subprocess
import sys
import pytest
from src.audit import audit_container, bind_source, is_host_root


@pytest.mark.parametrize("user", ["root", "0", "root:root", "0:1000"])
def test_explicit_root_is_reported(user):
    findings = audit_container({"Config": {"User": user}})
    assert any("root" in message.lower() for _, message in findings)


def test_structured_mounts_are_checked():
    findings = audit_container({"Config": {"User": "1000"}, "Mounts": [{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/sock"}]})
    assert any("Docker socket" in message for _, message in findings)


def test_all_containers_are_reviewed(tmp_path):
    path = tmp_path / "inspect.json"
    path.write_text(json.dumps([{"Name": "/safe", "Config": {"User": "1000"}}, {"Name": "/risky", "HostConfig": {"Privileged": True}}]))
    result = subprocess.run([sys.executable, "-m", "src.audit", str(path)], capture_output=True, text=True)
    assert result.returncode == 0
    assert "privileged" in result.stdout
    assert "/risky" in result.stdout


@pytest.mark.parametrize("payload", [{"HostConfig": []}, {"Config": "bad"}, {"NetworkSettings": {"Ports": []}}, {"Mounts": [None]}])
def test_invalid_inspect_shapes_are_rejected(payload):
    with pytest.raises(ValueError):
        audit_container(payload)


def test_empty_bind_source_is_not_treated_as_host_root():
    findings = audit_container({"Config": {"User": "1000"}, "HostConfig": {"Binds": [""]}})
    assert not any("Host root" in message for _, message in findings)


def test_host_root_bind_is_still_reported():
    findings = audit_container({"Config": {"User": "1000"}, "HostConfig": {"Binds": ["/:/host"]}})
    assert any("Host root" in message for _, message in findings)


def test_numeric_uid_zero_is_reported_as_root():
    findings = audit_container({"Config": {"User": 0}, "HostConfig": {"Binds": []}})
    assert any("UID 0" in message for _, message in findings)


def test_windows_drive_bind_keeps_its_drive_letter():
    assert bind_source("C:\\data:/container") == "C:\\data"
    assert bind_source("/data:/container") == "/data"
    findings = audit_container(
        {"Config": {"User": "1000"}, "HostConfig": {"Binds": ["C:\\data:/container"]}}
    )
    assert not any("Host root" in message for _, message in findings)


def test_windows_drive_root_bind_is_reported():
    assert is_host_root("C:") and is_host_root("/") and not is_host_root("C:\\data")
    findings = audit_container(
        {"Config": {"User": "1000"}, "HostConfig": {"Binds": ["C:\\:/container"]}}
    )
    assert any("Host root" in message for _, message in findings)
