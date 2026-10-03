"""Every extended check is exercised through audit_container."""
import copy

import pytest

from src.audit import audit_container

CLEAN = {
    "Config": {
        "Image": "app@sha256:" + "0" * 64,
        "User": "1000",
        "Env": ["APP_MODE=production"],
        "Healthcheck": {"Test": ["CMD", "true"]},
    },
    "HostConfig": {
        "Privileged": False,
        "NetworkMode": "bridge",
        "PidMode": "",
        "IpcMode": "",
        "CapAdd": [],
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


def container(**sections):
    """A clean container with only the named sections overridden."""
    info = copy.deepcopy(CLEAN)
    for section, values in sections.items():
        if isinstance(values, dict) and isinstance(info.get(section), dict):
            info[section].update(values)
        else:
            info[section] = copy.deepcopy(values)
    return info


def evidence(findings):
    return " ".join(finding.evidence for finding in findings)


def test_clean_container_has_no_findings():
    assert audit_container(container()) == []


def test_privileged_mode_is_high():
    findings = audit_container(container(HostConfig={"Privileged": True}))
    finding = next(f for f in findings if "Privileged" in f.evidence)
    assert finding.severity == "HIGH"
    assert finding.control == "CIS Docker Benchmark 5.4"


def test_host_pid_namespace_is_flagged():
    findings = audit_container(container(HostConfig={"PidMode": "host"}))
    assert any("host PID namespace" in f.explanation for f in findings)


def test_host_ipc_namespace_is_flagged():
    findings = audit_container(container(HostConfig={"IpcMode": "host"}))
    assert any(f.severity == "MEDIUM" and "host IPC namespace" in f.explanation for f in findings)


def test_host_network_namespace_is_high():
    findings = audit_container(container(HostConfig={"NetworkMode": "host"}))
    finding = next(f for f in findings if "NetworkMode" in f.evidence)
    assert finding.severity == "HIGH"
    assert "host network namespace" in finding.explanation


def test_shared_container_namespace_is_flagged():
    findings = audit_container(container(HostConfig={"NetworkMode": "container:abc"}))
    assert any("another container's network namespace" in f.explanation for f in findings)


@pytest.mark.parametrize("capability", ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_READ_SEARCH"])
def test_dangerous_capabilities_are_named_individually(capability):
    findings = audit_container(container(HostConfig={"CapAdd": [capability]}))
    assert any(capability in f.evidence for f in findings)


def test_dangerous_capability_is_high_with_control():
    findings = audit_container(container(HostConfig={"CapAdd": ["SYS_ADMIN"]}))
    finding = next(f for f in findings if "SYS_ADMIN" in f.evidence)
    assert finding.severity == "HIGH"
    assert finding.control == "CIS Docker Benchmark 5.3"


def test_unknown_capability_is_medium():
    findings = audit_container(container(HostConfig={"CapAdd": ["FOO_BAR"]}))
    finding = next(f for f in findings if "FOO_BAR" in f.evidence)
    assert finding.severity == "MEDIUM"


def test_cap_add_all_is_high():
    findings = audit_container(container(HostConfig={"CapAdd": ["ALL"]}))
    assert any(f.severity == "HIGH" and "CapAdd includes ALL" in f.evidence for f in findings)


def test_capdrop_all_clears_the_default_capability_finding():
    findings = audit_container(container(HostConfig={"CapDrop": ["ALL"]}))
    assert not any("CapDrop" in f.evidence for f in findings)


def test_missing_capdrop_reports_default_capabilities():
    findings = audit_container(container(HostConfig={"CapDrop": []}))
    assert any("CapDrop does not include ALL" in f.evidence for f in findings)


def test_writable_root_filesystem_is_flagged():
    findings = audit_container(container(HostConfig={"ReadonlyRootfs": False}))
    assert any("ReadonlyRootfs" in f.evidence for f in findings)


def test_read_only_root_filesystem_is_accepted():
    findings = audit_container(container(HostConfig={"ReadonlyRootfs": True}))
    assert not any("ReadonlyRootfs" in f.evidence for f in findings)


def test_seccomp_unconfined_is_high():
    findings = audit_container(container(HostConfig={"SecurityOpt": ["seccomp=unconfined"]}))
    finding = next(f for f in findings if "seccomp" in f.evidence)
    assert finding.severity == "HIGH"
    assert finding.control == "CIS Docker Benchmark 5.10"


def test_apparmor_unconfined_is_medium():
    findings = audit_container(container(HostConfig={"SecurityOpt": ["apparmor=unconfined"]}))
    assert any(f.severity == "MEDIUM" and "AppArmor" in f.evidence for f in findings)


def test_seccomp_profile_field_is_honoured():
    findings = audit_container(container(HostConfig={"SeccompProfile": "unconfined"}))
    assert any("seccomp" in f.evidence for f in findings)


def test_declared_non_root_user_is_accepted():
    findings = audit_container(container(Config={"User": "1000"}))
    assert not any("Config.User" in f.evidence for f in findings)


def test_empty_user_is_flagged():
    findings = audit_container(container(Config={"User": ""}))
    assert any(f.severity == "MEDIUM" and "Config.User is empty" in f.evidence for f in findings)


def test_root_user_is_flagged():
    findings = audit_container(container(Config={"User": "root"}))
    assert any("Config.User is root" in f.evidence for f in findings)


def test_docker_socket_mount_is_high_with_its_control():
    findings = audit_container(container(HostConfig={"Binds": ["/var/run/docker.sock:/sock"]}))
    finding = next(f for f in findings if "docker.sock" in f.evidence)
    assert finding.severity == "HIGH"
    assert finding.control == "CIS Docker Benchmark 5.31"


def test_host_etc_mount_read_write_is_high():
    findings = audit_container(container(HostConfig={"Binds": ["/etc:/host-etc"]}))
    finding = next(f for f in findings if "/etc" in f.evidence)
    assert finding.severity == "HIGH"
    assert "read-write" in finding.evidence


def test_host_etc_mount_read_only_is_downgraded():
    findings = audit_container(container(HostConfig={"Binds": ["/etc:/host-etc:ro"]}))
    finding = next(f for f in findings if "/etc" in f.evidence)
    assert finding.severity == "MEDIUM"
    assert "read-only" in finding.evidence


def test_proc_sys_and_dev_mounts_are_reported():
    findings = audit_container(container(HostConfig={"Binds": ["/proc:/proc", "/sys:/sys:ro", "/dev:/dev"]}))
    labels = {f.evidence.split()[4] for f in findings if "Sensitive bind mount" in f.evidence}
    assert {"/proc", "/sys", "/dev"} <= labels


def test_duplicate_bind_and_structured_mount_report_once():
    info = container(
        HostConfig={"Binds": ["/var/run/docker.sock:/var/run/docker.sock"]},
        Mounts=[{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": True, "Mode": ""}],
    )
    findings = audit_container(info)
    assert sum(1 for f in findings if "docker.sock" in f.evidence) == 1


def test_port_bound_to_all_interfaces_is_medium():
    findings = audit_container(container(NetworkSettings={"Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}]}}))
    assert any(f.severity == "MEDIUM" and "all interfaces" in f.evidence for f in findings)


def test_port_bound_to_loopback_is_not_flagged():
    findings = audit_container(container(NetworkSettings={"Ports": {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "80"}]}}))
    assert not any("all interfaces" in f.evidence for f in findings)


def test_empty_host_ip_counts_as_all_interfaces():
    findings = audit_container(container(NetworkSettings={"Ports": {"80/tcp": [{"HostIp": "", "HostPort": "80"}]}}))
    assert any("all interfaces" in f.evidence for f in findings)


def test_exposed_but_unpublished_port_is_ignored():
    findings = audit_container(container(NetworkSettings={"Ports": {"80/tcp": None}}))
    assert not any("all interfaces" in f.evidence for f in findings)


def test_portbindings_fallback_is_used():
    info = container(HostConfig={"PortBindings": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}]}})
    findings = audit_container(info)
    assert any("all interfaces" in f.evidence for f in findings)


def test_floating_latest_tag_is_flagged():
    findings = audit_container(container(Config={"Image": "nginx:latest"}))
    assert any(f.severity == "LOW" and "latest tag" in f.evidence for f in findings)


def test_tagless_image_is_flagged():
    findings = audit_container(container(Config={"Image": "nginx"}))
    assert any("has no tag" in f.evidence for f in findings)


def test_digest_pinned_image_is_accepted():
    findings = audit_container(container(Config={"Image": "nginx@sha256:" + "a" * 64}))
    assert not any("tag" in f.evidence for f in findings)


def test_registry_port_is_not_mistaken_for_a_tag():
    findings = audit_container(container(Config={"Image": "registry.local:5000/team/app"}))
    assert any("has no tag" in f.evidence for f in findings)


def test_missing_healthcheck_is_flagged():
    info = container()
    del info["Config"]["Healthcheck"]
    findings = audit_container(info)
    assert any("Healthcheck is absent" in f.evidence for f in findings)


def test_disabled_healthcheck_is_flagged():
    findings = audit_container(container(Config={"Healthcheck": {"Test": ["NONE"]}}))
    assert any("Healthcheck is disabled" in f.evidence for f in findings)


def test_restart_always_is_flagged():
    findings = audit_container(container(HostConfig={"RestartPolicy": {"Name": "always"}}))
    assert any("RestartPolicy" in f.evidence for f in findings)


def test_restart_on_failure_is_accepted():
    findings = audit_container(container(HostConfig={"RestartPolicy": {"Name": "on-failure"}}))
    assert not any("RestartPolicy" in f.evidence for f in findings)


def test_absent_restart_policy_is_flagged():
    info = container()
    del info["HostConfig"]["RestartPolicy"]
    findings = audit_container(info)
    assert any("RestartPolicy is absent" in f.evidence for f in findings)


def test_missing_memory_limit_is_flagged():
    findings = audit_container(container(HostConfig={"Memory": 0}))
    assert any("Memory is not set" in f.evidence for f in findings)


def test_memory_limit_is_accepted():
    findings = audit_container(container(HostConfig={"Memory": 268435456}))
    assert not any("Memory is not set" in f.evidence for f in findings)


def test_missing_cpu_limit_is_flagged():
    findings = audit_container(container(HostConfig={"NanoCpus": 0, "CpuQuota": 0}))
    assert any("No CPU quota" in f.evidence for f in findings)


def test_cpu_quota_is_accepted():
    findings = audit_container(container(HostConfig={"NanoCpus": 0, "CpuQuota": 50000}))
    assert not any("No CPU quota" in f.evidence for f in findings)


@pytest.mark.parametrize("name", ["DB_PASSWORD", "API_KEY", "AUTH_TOKEN", "AWS_SECRET_ACCESS_KEY", "MYSQL_ROOT_PASSWORD"])
def test_secret_looking_env_is_flagged(name):
    findings = audit_container(container(Config={"Env": [f"{name}=value123"]}))
    assert any("Secret-looking environment variables" in f.evidence for f in findings)


def test_empty_secret_value_is_not_flagged():
    findings = audit_container(container(Config={"Env": ["DB_PASSWORD="]}))
    assert not any("Secret-looking" in f.evidence for f in findings)


def test_non_secret_env_is_not_flagged():
    findings = audit_container(container(Config={"Env": ["MONKEY=banana", "APP_MODE=prod"]}))
    assert not any("Secret-looking" in f.evidence for f in findings)


def test_secret_value_is_not_printed():
    findings = audit_container(container(Config={"Env": ["DB_PASSWORD=hunter2"]}))
    assert not any("hunter2" in f.evidence or "hunter2" in f.explanation for f in findings)


def test_external_log_driver_is_flagged():
    findings = audit_container(container(HostConfig={"LogConfig": {"Type": "syslog", "Config": {}}}))
    assert any("Log driver is" in f.evidence for f in findings)


def test_missing_log_limit_is_flagged():
    findings = audit_container(container(HostConfig={"LogConfig": {"Type": "json-file", "Config": {}}}))
    assert any("no size limit" in f.evidence for f in findings)


def test_log_limit_is_accepted():
    findings = audit_container(container(HostConfig={"LogConfig": {"Type": "json-file", "Config": {"max-size": "10m"}}}))
    assert not any("no size limit" in f.evidence for f in findings)


@pytest.mark.parametrize("payload", [
    {"HostConfig": {"CapAdd": "SYS_ADMIN"}},
    {"HostConfig": {"CapDrop": "ALL"}},
    {"HostConfig": {"SecurityOpt": "seccomp=unconfined"}},
    {"HostConfig": {"RestartPolicy": "always"}},
    {"HostConfig": {"LogConfig": "json-file"}},
    {"Config": {"Env": "A=B"}},
    {"Config": {"Healthcheck": "none"}},
])
def test_invalid_shapes_are_rejected(payload):
    with pytest.raises(ValueError):
        audit_container(payload)
