"""The Kubernetes assessor: manifests, read as the cluster would read them.

A manifest is a statement of intent about a workload, and most of the container
hardening in the policy is expressed here rather than in the image -- the same image
can run as root in one cluster and not in another, and the difference is four lines
of YAML.

The assessor reads every workload kind that carries a pod template, follows the
`containers` and `initContainers` lists, and checks the pod-level security context
as well as the container-level one, because Kubernetes merges them and a setting in
either place is a setting.
"""

from __future__ import annotations

import re
from pathlib import Path

from .findings import Evidence, make

__all__ = ["assess_kubernetes", "WORKLOAD_KINDS"]

ENVIRONMENT = "kubernetes"

# The kinds that carry a pod template. A manifest of another kind is not ignored --
# it is checked for the controls that apply to any object, like a wildcard role.
WORKLOAD_KINDS = ("Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
                  "Job", "CronJob", "ReplicationController")

# Ports whose exposure is the finding, whatever the credential is. These are the
# ports an operator uses to administer something.
MANAGEMENT_PORTS = (22, 23, 2375, 2376, 3306, 5432, 6379, 9200, 11211, 27017, 8080,
                    8443, 9000, 10250)

_SECRET_KEY = re.compile(r"(?:password|passwd|secret|token|api[-_]?key|private[-_]?key)",
                         re.IGNORECASE)
_PLACEHOLDER = re.compile(r"^(?:changeme|placeholder|example|<[^>]+>|\$\{?[A-Z_]+\}?)$",
                          re.IGNORECASE)


def _documents(text: str) -> list:
    import yaml
    documents = []
    for document in yaml.safe_load_all(text):
        if isinstance(document, dict) and document:
            documents.append(document)
    return documents


def _pod_spec(manifest: dict):
    """The pod template inside a workload, wherever that kind keeps it."""
    kind = manifest.get("kind")
    if kind == "Pod":
        return manifest.get("spec") or {}
    if kind == "CronJob":
        return (((manifest.get("spec") or {}).get("jobTemplate") or {})
                .get("spec") or {}).get("template", {}).get("spec") or {}
    return ((manifest.get("spec") or {}).get("template") or {}).get("spec") or {}


def _containers(spec: dict):
    for key in ("containers", "initContainers"):
        for container in spec.get(key) or []:
            if isinstance(container, dict):
                yield key, container


def assess_kubernetes(policy, text: str, target: str = "manifest.yaml") -> list:
    """Check every document in a manifest against the Kubernetes controls."""
    findings = []
    try:
        documents = _documents(text)
    except Exception:
        return findings

    for manifest in documents:
        kind = manifest.get("kind") or "?"
        name = (manifest.get("metadata") or {}).get("name") or "unnamed"
        where = "%s: %s/%s" % (target, kind, name)

        # --- role-based access -------------------------------------------
        if kind in ("Role", "ClusterRole"):
            for rule in manifest.get("rules") or []:
                if not isinstance(rule, dict):
                    continue
                actions = rule.get("verbs") or []
                resources = rule.get("resources") or []
                if "*" in actions or "*" in resources:
                    evidence = Evidence()
                    evidence.add("rule", where, "verbs=%s resources=%s"
                                 % (actions, resources))
                    findings.append(make(
                        policy.by_id("least-privilege-iam"), ENVIRONMENT, target,
                        "The role grants a wildcard. A wildcard is a permission nobody "
                        "had to think about, which is why it accumulates.", evidence,
                        location=where))
                    break

        if kind in ("ClusterRoleBinding", "RoleBinding"):
            for subject in manifest.get("subjects") or []:
                if isinstance(subject, dict) and subject.get("kind") == "Group" \
                        and subject.get("name") in ("system:unauthenticated",
                                                    "system:authenticated"):
                    evidence = Evidence()
                    evidence.add("subject", where, "group: %s" % subject.get("name"))
                    findings.append(make(
                        policy.by_id("no-anonymous-access"), ENVIRONMENT, target,
                        "The binding grants access to an unauthenticated group, which is "
                        "an interface with no password rather than a weak one.", evidence,
                        location=where))
                    break

        # A Service is not a workload kind and carries no pod template, but it is
        # where a management port gets published. This check used to sit after the
        # continue below, so a Service was never examined at all -- the manifest
        # declared a NodePort on 22 and the assessor reported nothing.
        if kind == "Service":
            service_type = (manifest.get("spec") or {}).get("type")
            for port in (manifest.get("spec") or {}).get("ports") or []:
                if not isinstance(port, dict):
                    continue
                number = port.get("port")
                if service_type == "NodePort" and number in MANAGEMENT_PORTS:
                    evidence = Evidence()
                    evidence.add("service", where, "type: NodePort, port: %s" % number)
                    findings.append(make(
                        policy.by_id("no-exposed-management-port"), ENVIRONMENT, target,
                        "A management port is published on every node in the cluster.",
                        evidence, location=where))
                    break
            continue

        if kind not in WORKLOAD_KINDS:
            continue

        spec = _pod_spec(manifest)
        pod_context = spec.get("securityContext") or {}

        if spec.get("hostNetwork") is True:
            evidence = Evidence()
            evidence.add("pod spec", where, "hostNetwork: true")
            findings.append(make(
                policy.by_id("no-host-network"), ENVIRONMENT, target,
                "The pod shares the node's network namespace, so it can reach everything "
                "the node can.", evidence, location=where))

        if str(spec.get("hostPID")) == "True" or spec.get("hostPID") is True:
            evidence = Evidence()
            evidence.add("pod spec", where, "hostPID: true")
            findings.append(make(
                policy.by_id("no-privileged-container"), ENVIRONMENT, target,
                "The pod shares the node's process namespace, so it can see and signal "
                "every process on the node.", evidence, location=where))

        for key, container in _containers(spec):
            cname = container.get("name") or "?"
            cwhere = "%s (%s)" % (where, cname)
            context = container.get("securityContext") or {}

            runs_as_root = (context.get("runAsUser") in (0, "0")
                            or pod_context.get("runAsUser") in (0, "0")
                            or context.get("runAsNonRoot") is False
                            or pod_context.get("runAsNonRoot") is False)
            declares_non_root = (context.get("runAsNonRoot") is True
                                 or pod_context.get("runAsNonRoot") is True
                                 or (context.get("runAsUser") not in (None, 0, "0")
                                     and pod_context.get("runAsUser") not in (None, 0, "0")))
            if runs_as_root or not declares_non_root:
                evidence = Evidence()
                evidence.add("container", cwhere,
                             "runAsNonRoot=%s runAsUser=%s"
                             % (context.get("runAsNonRoot", pod_context.get("runAsNonRoot")),
                                context.get("runAsUser", pod_context.get("runAsUser"))))
                findings.append(make(
                    policy.by_id("no-root-user"), ENVIRONMENT, target,
                    "The container does not require a non-root user. Kubernetes will "
                    "admit a manifest that runs as root, so the requirement has to be "
                    "stated for it to mean anything.", evidence, location=cwhere))

            if context.get("privileged") is True:
                evidence = Evidence()
                evidence.add("container", cwhere, "privileged: true")
                findings.append(make(
                    policy.by_id("no-privileged-container"), ENVIRONMENT, target,
                    "The container runs privileged, which gives it the node's "
                    "capabilities.", evidence, location=cwhere))

            if context.get("readOnlyRootFilesystem") is not True:
                evidence = Evidence()
                evidence.add("container", cwhere, "readOnlyRootFilesystem is %s"
                             % ("absent" if "readOnlyRootFilesystem" not in context
                                else context["readOnlyRootFilesystem"]))
                findings.append(make(
                    policy.by_id("read-only-root-filesystem"), ENVIRONMENT, target,
                    "The root filesystem is writable, so anything that gets in can "
                    "persist.", evidence, location=cwhere))

            resources = container.get("resources") or {}
            if not (resources.get("limits") or {}):
                evidence = Evidence()
                evidence.add("container", cwhere, "resources.limits is empty")
                findings.append(make(
                    policy.by_id("resource-limits-set"), ENVIRONMENT, target,
                    "The container declares no limit, so it can consume the node.",
                    evidence, location=cwhere))

            image = str(container.get("image") or "")
            if image:
                tag = image.rsplit(":", 1)[1] if ":" in image.split("/")[-1] else ""
                if tag in ("", "latest"):
                    evidence = Evidence()
                    evidence.add("container", cwhere, "image: %s" % image)
                    findings.append(make(
                        policy.by_id("no-latest-tag"), ENVIRONMENT, target,
                        "The image tag moves, so the manifest does not say which artifact "
                        "runs.", evidence, location=cwhere))

            for entry in container.get("env") or []:
                if not isinstance(entry, dict):
                    continue
                key = str(entry.get("name") or "")
                if not _SECRET_KEY.search(key):
                    continue
                value = entry.get("value")
                if value is None:
                    continue                     # a valueFrom reference is the right shape
                if _PLACEHOLDER.match(str(value).strip()):
                    continue
                evidence = Evidence()
                evidence.add("env", "%s name=%s" % (cwhere, key),
                             "a literal value rather than a secretKeyRef")
                findings.append(make(
                    policy.by_id("no-secrets-in-configuration"), ENVIRONMENT, target,
                    "A credential is written into the manifest, which is a file in "
                    "version control and in every clone of it.", evidence, location=cwhere))
                break

            for port in container.get("ports") or []:
                if not isinstance(port, dict):
                    continue
                if port.get("hostPort"):
                    evidence = Evidence()
                    evidence.add("port", cwhere, "hostPort: %s" % port.get("hostPort"))
                    findings.append(make(
                        policy.by_id("no-exposed-management-port"), ENVIRONMENT, target,
                        "The container binds a port on the node itself, which is outside "
                        "the pod boundary.", evidence, location=cwhere))
                    break

    return findings


def assess_kubernetes_file(policy, path: str | Path) -> list:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError("no such manifest: %s" % path)
    return assess_kubernetes(policy, path.read_text(encoding="utf-8", errors="replace"),
                             target=path.name)
