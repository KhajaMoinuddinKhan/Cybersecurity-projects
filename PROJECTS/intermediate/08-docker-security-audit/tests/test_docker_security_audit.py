from src.audit import audit_container

def test_privileged_and_host_network_are_flagged():
    findings=audit_container({
        "Config":{"User":""},
        "HostConfig":{"Privileged":True,"NetworkMode":"host"},
        "NetworkSettings":{"Ports":{}},
    })
    messages=" ".join(message for _,message in findings).lower()
    assert "privileged" in messages
    assert "host network" in messages
