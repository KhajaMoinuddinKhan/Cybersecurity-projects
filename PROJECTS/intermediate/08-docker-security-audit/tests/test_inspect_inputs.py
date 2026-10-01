import json
import subprocess
import sys
import pytest
from src.audit import audit_container


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
