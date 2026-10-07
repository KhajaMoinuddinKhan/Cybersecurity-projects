"""The policy engine, and the four assessors, against the lab.

The lab declares what is wrong with each of its artifacts, and these tests check the
assessors find exactly that -- no more and no less. A fixture that stops exercising a
control fails here rather than passing quietly, which is the failure mode that matters
most for a tool whose output is a list of problems: a check that has silently stopped
looking reports a clean estate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lab import Broker, LAB_DIR, manifest
from src.container import assess_compose, assess_container, parse_dockerfile
from src.iac import assess_terraform_file, parse_blocks
from src.iot import assess_broker, assess_device, load_inventory
from src.kubernetes import assess_kubernetes_file
from src.policy import DEFAULT_POLICY_PATH, PolicyError, load_policy
from src.risk import build_register, summarise

LAB = LAB_DIR


@pytest.fixture(scope="module")
def policy():
    return load_policy(DEFAULT_POLICY_PATH)


@pytest.fixture(scope="module")
def declared():
    return manifest()


def controls_for(policy, path_name):
    """The controls the lab says this artifact violates, as a set."""
    return set(manifest()["artifacts"].get(path_name, []))


def ids(findings):
    return {f.control_id for f in findings}


# --- the policy ------------------------------------------------------------

def test_the_shipped_policy_loads(policy):
    assert policy.version == 1
    assert len(policy.controls) >= 10
    assert set(policy.environments) == {"container", "kubernetes", "iac", "iot"}


def test_every_environment_has_controls_behind_it(policy):
    """An environment the policy names and nothing checks is the platform claiming
    coverage it does not have."""
    for environment in policy.environments:
        assert policy.for_environment(environment), environment


def test_every_control_names_the_standard_it_implements(policy):
    for control in policy.controls:
        assert control.cis or control.iso27001, control.id
        assert control.iso27001.startswith("A."), control.id
        assert control.nist_csf, control.id
        assert control.intent and control.remediation, control.id
        assert control.owner, control.id


def test_the_iso_and_csf_references_are_the_ones_the_policy_claims(policy):
    """The mapping is asserted in the report, so the values behind it are checked."""
    for control in policy.controls:
        assert control.iso27001.split()[0].startswith("A.")
        # "PR.AA Identity, Authentication and Access Control" -- the function is the
        # part before the dot, the category is the whole first token.
        assert control.nist_csf.split()[0].split(".")[0] in (
            "GV", "ID", "PR", "DE", "RS", "RC"), control.nist_csf


def test_a_control_naming_an_unknown_environment_is_refused(tmp_path):
    bad = tmp_path / "p.yaml"
    bad.write_text("""
version: 1
environments: [container]
controls:
  - id: x
    title: t
    intent: i
    applies_to: [iot]
    severity: high
    remediation: r
""", encoding="utf-8")
    with pytest.raises(PolicyError) as exc:
        load_policy(bad)
    assert "iot" in str(exc.value)


def test_an_environment_with_no_controls_is_refused(tmp_path):
    bad = tmp_path / "p.yaml"
    bad.write_text("""
version: 1
environments: [container, iot]
controls:
  - id: x
    title: t
    intent: i
    applies_to: [container]
    severity: high
    remediation: r
""", encoding="utf-8")
    with pytest.raises(PolicyError) as exc:
        load_policy(bad)
    assert "iot" in str(exc.value)


def test_two_controls_with_one_id_are_refused(tmp_path):
    bad = tmp_path / "p.yaml"
    bad.write_text("""
version: 1
environments: [container]
controls:
  - {id: x, title: t, intent: i, applies_to: [container], severity: high, remediation: r}
  - {id: x, title: u, intent: j, applies_to: [container], severity: low, remediation: s}
""", encoding="utf-8")
    with pytest.raises(PolicyError) as exc:
        load_policy(bad)
    assert "share the id" in str(exc.value)


def test_a_control_with_no_intent_is_refused(tmp_path):
    bad = tmp_path / "p.yaml"
    bad.write_text("""
version: 1
environments: [container]
controls:
  - {id: x, title: t, applies_to: [container], severity: high, remediation: r}
""", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(bad)


def test_a_wrong_policy_version_is_refused(tmp_path):
    bad = tmp_path / "p.yaml"
    bad.write_text("version: 99\nenvironments: [container]\ncontrols: []\n", encoding="utf-8")
    with pytest.raises(PolicyError) as exc:
        load_policy(bad)
    assert "version" in str(exc.value)


# --- the container assessor ------------------------------------------------

def test_the_dockerfile_parser_joins_continuations():
    instructions = parse_dockerfile("FROM x\nRUN a \\\n  && b\nUSER app\n")
    assert [name for name, _, _ in instructions] == ["FROM", "RUN", "USER"]
    assert "&& b" in instructions[1][1]


def test_the_dockerfile_parser_keeps_line_numbers():
    instructions = parse_dockerfile("# a comment\n\nFROM x\n")
    assert instructions[0][2] == 3


def test_the_vulnerable_dockerfile_violates_exactly_the_declared_controls(policy, declared):
    found = assess_container(policy, LAB / "Dockerfile.vulnerable")
    assert ids(found) == controls_for(policy, "Dockerfile.vulnerable")


def test_the_hardened_dockerfile_violates_nothing(policy):
    found = assess_container(policy, LAB / "Dockerfile.hardened")
    assert found == [], [f.control_id for f in found]


def test_a_dockerfile_with_no_user_instruction_is_a_finding(policy):
    found = assess_container(policy, LAB / "Dockerfile.vulnerable")
    root = [f for f in found if f.control_id == "no-root-user"]
    assert root and "never names a user" in root[0].detail


def test_a_placeholder_credential_is_not_reported_as_a_leak(policy, tmp_path):
    """Telling somebody their example password is a leak wastes their time and
    teaches them to ignore the check."""
    path = tmp_path / "Dockerfile"
    path.write_text("FROM python:3.12-slim\nUSER app\nENV DB_PASSWORD=changeme\n",
                    encoding="utf-8")
    assert assess_container(policy, path) == []


def test_a_real_looking_credential_is_reported(policy, tmp_path):
    path = tmp_path / "Dockerfile"
    path.write_text("FROM python:3.12-slim\nUSER app\n"
                    "ENV API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123456789\n", encoding="utf-8")
    assert "no-secrets-in-configuration" in ids(assess_container(policy, path))


def test_the_vulnerable_compose_violates_exactly_the_declared_controls(policy, declared):
    found = assess_container(policy, LAB / "docker-compose.vulnerable.yml")
    assert ids(found) == controls_for(policy, "docker-compose.vulnerable.yml")


def test_the_clean_service_in_the_compose_file_is_not_reported(policy):
    """One service in the compose file is configured properly, and the findings for
    it must be none -- a check that fires on the clean service is not checking."""
    found = assess_container(policy, LAB / "docker-compose.vulnerable.yml")
    cache = [f for f in found if "cache" in f.location]
    assert cache == [], [f.control_id for f in cache]


# --- the kubernetes assessor ------------------------------------------------

def test_the_vulnerable_manifest_violates_exactly_the_declared_controls(policy):
    found = assess_kubernetes_file(policy, LAB / "deployment.vulnerable.yaml")
    assert ids(found) == controls_for(policy, "deployment.vulnerable.yaml")


def test_the_hardened_manifest_violates_nothing(policy):
    found = assess_kubernetes_file(policy, LAB / "deployment.hardened.yaml")
    assert found == [], [f.control_id for f in found]


def test_a_wildcard_role_is_reported(policy):
    found = assess_kubernetes_file(policy, LAB / "deployment.vulnerable.yaml")
    wildcard = [f for f in found if f.control_id == "least-privilege-iam"]
    assert wildcard and "ClusterRole/do-everything" in wildcard[0].location


def test_a_service_publishing_a_management_port_is_reported(policy):
    found = assess_kubernetes_file(policy, LAB / "deployment.vulnerable.yaml")
    exposed = [f for f in found if f.control_id == "no-exposed-management-port"]
    # the detail is where it was found; the value carries what was seen
    assert any("NodePort" in item.get("value", "")
               for f in exposed for item in f.evidence), \
        "the Service publishing port 22 as a NodePort has to be among them"


def test_a_secret_from_a_secretref_is_not_a_finding(policy):
    """The hardened manifest references a secret; the vulnerable one writes a value."""
    hardened = assess_kubernetes_file(policy, LAB / "deployment.hardened.yaml")
    assert "no-secrets-in-configuration" not in ids(hardened)


# --- the IaC assessor -------------------------------------------------------

def test_the_block_parser_reads_resources_and_nested_blocks():
    root = parse_blocks('resource "aws_security_group" "web" {\n  ingress {\n    from_port = 22\n  }\n}\n')
    resources = [b for b in root["blocks"] if b["type"] == "resource"]
    assert resources[0]["kind"] == "aws_security_group"
    assert resources[0]["name"] == "web"
    assert resources[0]["blocks"][0]["type"] == "ingress"
    assert resources[0]["blocks"][0]["attributes"]["from_port"] == "22"


def test_the_terraform_violates_exactly_the_declared_controls(policy):
    found = assess_terraform_file(policy, LAB / "main.tf")
    assert ids(found) == controls_for(policy, "main.tf")


def test_a_rule_whose_ports_come_from_a_variable_is_reported_as_unknown(policy):
    """The honest answer. Reading it as clear would be a false negative, and a false
    negative is the failure mode that matters for a tool like this."""
    found = assess_terraform_file(policy, LAB / "main.tf")
    unknown = [f for f in found if f.control_id == "no-exposed-management-port"
               and "cannot be read" in f.detail]
    assert unknown, "the variable-port rule should be reported as unevaluated"
    assert "unknown rather than clear" in unknown[0].detail


def test_a_variable_reference_is_not_reported_as_a_hardcoded_secret(policy, tmp_path):
    path = tmp_path / "main.tf"
    path.write_text('resource "aws_db_instance" "x" {\n  password = var.db_password\n}\n',
                    encoding="utf-8")
    found = assess_terraform_file(policy, path)
    assert "no-secrets-in-configuration" not in ids(found)


def test_a_literal_secret_is_reported(policy, tmp_path):
    path = tmp_path / "main.tf"
    path.write_text('resource "aws_db_instance" "x" {\n  password = "a-literal-password"\n}\n',
                    encoding="utf-8")
    assert "no-secrets-in-configuration" in ids(assess_terraform_file(policy, path))


# --- the IoT assessor, against a real broker --------------------------------

@pytest.fixture(scope="module")
def open_broker():
    with Broker(allow_anonymous=True) as broker:
        yield broker


@pytest.fixture(scope="module")
def closed_broker():
    with Broker(allow_anonymous=False) as broker:
        yield broker


def test_an_open_broker_is_reported(policy, open_broker):
    """A real broker, accepting a connection from anyone. Nothing about this is
    simulated -- the CONNECT packet goes out and the CONNACK comes back."""
    host, port = open_broker.address.split(":")
    found = assess_broker(policy, host, int(port))
    assert "no-anonymous-access" in ids(found)
    anonymous = [f for f in found if f.control_id == "no-anonymous-access"][0]
    assert "CONNACK code 0" in anonymous.evidence[0]["value"]


def test_a_closed_broker_is_not_reported(policy, closed_broker):
    """The negative case. A check that fires on the hardened configuration as well is
    not detecting anything, and the open-broker test alone could not tell."""
    host, port = closed_broker.address.split(":")
    found = assess_broker(policy, host, int(port))
    assert "no-anonymous-access" not in ids(found)


def test_an_unreachable_broker_is_reported_as_unknown_not_as_clear(policy):
    """"No answer" and "it refused me" are opposite conclusions."""
    found = assess_broker(policy, "127.0.0.1", 1, timeout=1.0)
    assert "no-anonymous-access" in ids(found)
    assert "unknown rather than as clear" in found[0].detail


def test_a_broker_reachable_from_a_network_is_a_finding(policy, open_broker):
    """A broker bound to a non-loopback address is a management interface on the
    network. The lab binds to loopback, so this is asserted against the address the
    check is given rather than by binding elsewhere."""
    _, port = open_broker.address.split(":")
    found = assess_broker(policy, "10.0.0.5", int(port), timeout=1.0)
    assert "no-exposed-management-port" in ids(found)


def test_a_device_with_no_update_path_is_a_finding(policy):
    found = assess_device(policy, {"name": "old-meter", "firmware": "0.9"})
    assert "firmware-update-path" in ids(found)


def test_a_device_with_a_signed_encrypted_update_path_is_clean(policy):
    found = assess_device(policy, {
        "name": "sensor", "firmware_update": {
            "url": "https://f.example.com/a.bin", "signature_verified": True}})
    assert found == []


def test_a_plaintext_update_path_is_a_finding(policy):
    found = assess_device(policy, {
        "name": "sensor", "firmware_update": {
            "url": "http://f.example.com/a.bin", "signature_verified": True}})
    assert "firmware-update-path" in ids(found)


def test_an_unsigned_update_path_is_a_finding(policy):
    found = assess_device(policy, {
        "name": "sensor", "firmware_update": {
            "url": "https://f.example.com/a.bin", "signature_verified": False}})
    assert "firmware-update-path" in ids(found)


def test_the_lab_inventory_violates_exactly_the_declared_controls(policy):
    devices = load_inventory(LAB / "inventory.json")
    found = []
    for device in devices:
        found.extend(assess_device(policy, device))
    assert ids(found) == set(manifest()["inventory.json"])


# --- the register -----------------------------------------------------------

def test_the_register_maps_every_entry_to_iso_and_csf(policy, open_broker):
    findings = assess_container(policy, LAB / "Dockerfile.vulnerable")
    entries = build_register(policy, findings)
    assert entries
    for entry in entries:
        assert entry.iso27001.startswith("A.")
        assert entry.nist_csf
        assert entry.owner
        assert entry.treatment
        assert entry.reference.startswith("RISK-")


def test_the_register_is_ordered_worst_first(policy):
    findings = (assess_container(policy, LAB / "Dockerfile.vulnerable")
                + assess_container(policy, LAB / "docker-compose.vulnerable.yml"))
    entries = build_register(policy, findings)
    ratings = [entry.severity for entry in entries]
    order = ("critical", "high", "medium", "low", "info")
    assert ratings == sorted(ratings, key=order.index)


def test_the_references_are_stable_for_the_same_findings(policy):
    """A register whose identifiers move between runs is one nobody can track a
    decision against."""
    findings = assess_container(policy, LAB / "Dockerfile.vulnerable")
    first = [e.reference for e in build_register(policy, findings)]
    second = [e.reference for e in build_register(policy, list(reversed(findings)))]
    assert first == second


def test_the_summary_reports_satisfied_controls_separately(policy):
    """A register showing only failures cannot distinguish a satisfied control from
    one that was never checked."""
    findings = assess_container(policy, LAB / "Dockerfile.vulnerable")
    summary = summarise(policy, build_register(policy, findings))
    assert summary["controls_satisfied"]
    assert summary["controls_violated"]
    assert len(summary["controls_satisfied"]) + len(summary["controls_violated"]) \
        == summary["controls_total"]
