from src.audit import audit_container


def _text(findings):
    return " ".join(f"{finding.severity} {finding.evidence} {finding.explanation}" for finding in findings).lower()


def test_privileged_and_host_network_are_flagged():
    findings = audit_container({
        "Config": {"User": ""},
        "HostConfig": {"Privileged": True, "NetworkMode": "host"},
        "NetworkSettings": {"Ports": {}},
    })
    messages = _text(findings)
    assert "privileged" in messages
    assert "host network" in messages


def test_exposed_but_unpublished_port_is_not_reported_as_published():
    findings = audit_container({
        "Config": {"User": "1000"},
        "HostConfig": {"Privileged": False, "NetworkMode": "bridge"},
        "NetworkSettings": {"Ports": {"80/tcp": None}},
    })
    messages = _text(findings)
    assert "published on all interfaces" not in messages
