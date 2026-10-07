"""The infrastructure-as-code assessor: Terraform.

The cloud estate is described before it exists, which makes this the one environment
where a control can be enforced before anything is deployed. It is also the one where
a mistake is cheapest to fix, and where it is easiest to make -- a security group
rule written once is copied into the next module and the next.

Parsing is a block reader rather than an HCL evaluator. It reads resource blocks,
their attributes and their nested blocks, and it does not resolve variables,
`locals`, or module outputs. That limit is real and it is stated: a rule built from
a variable is reported as unread rather than assumed to be safe, because assuming it
is safe is how a check becomes a false negative.
"""

from __future__ import annotations

import re
from pathlib import Path

from .findings import Evidence, make

__all__ = ["assess_terraform", "parse_blocks"]

ENVIRONMENT = "iac"

_OPEN = re.compile(r'^(\w+)\s+(?:"([^"]*)"\s*)?(?:"([^"]*)"\s*)?\{')
_ATTRIBUTE = re.compile(r'^(\w+)\s*=\s*(.+?)\s*$')

MANAGEMENT_PORTS = (22, 23, 3389, 3306, 5432, 6379, 9200, 27017, 2375, 2376, 8080, 8443)

_SECRET_KEY = re.compile(r"(?:password|passwd|secret|token|api[-_]?key|private[-_]?key|"
                         r"access[-_]?key)", re.IGNORECASE)
_PLACEHOLDER = re.compile(r'^(?:"")?$|^(?:"?(?:changeme|placeholder|example|var\.|local\.|'
                          r'data\.|"\$\{)[^"]*"?)$', re.IGNORECASE)


def parse_blocks(text: str) -> list:
    """Resource and data blocks with their attributes and nested blocks.

    Two things a line-oriented reader gets wrong, and both of them cost findings:

    A heredoc's body is text, not configuration. Its braces were being read as
    blocks, which unbalanced the stack and swallowed every resource after it -- so a
    file with an inline IAM policy reported nothing about the resources below it.
    The body is captured into the attribute rather than discarded, because the
    wildcard check needs to read it.

    A multi-line expression closes with a bracket, not with the block's brace. A
    `container_definitions = jsonencode([...])` spanning twenty lines ended the
    resource at its first `}`, so the container inside was never examined. Depth is
    tracked per attribute so that a value's own brackets are not mistaken for the
    end of the block.
    """
    root = {"type": "root", "kind": "root", "name": "", "attributes": {}, "blocks": [],
            "raw": [], "line": 0}
    stack = [root]
    heredoc = None
    heredoc_target = None
    depth = 0                      # brackets opened by a multi-line attribute value

    for number, raw in enumerate(str(text or "").splitlines(), 1):
        stripped = raw.strip()
        stack[-1]["raw"].append(raw)

        if heredoc is not None:
            if stripped == heredoc or stripped == heredoc + ";":
                heredoc = None
            else:
                heredoc_target["attributes"][heredoc_target["_heredoc_key"]] = (
                    heredoc_target["attributes"].get(heredoc_target["_heredoc_key"], "")
                    + raw + "\n")
            continue

        opener = re.search(r"<<-?\s*([A-Za-z_][A-Za-z0-9_]*)", raw)
        if opener:
            attribute = _ATTRIBUTE.match(raw.split("#", 1)[0].strip())
            if attribute:
                stack[-1]["attributes"][attribute.group(1)] = ""
                stack[-1]["_heredoc_key"] = attribute.group(1)
                heredoc_target = stack[-1]
            heredoc = opener.group(1)
            continue

        if depth > 0:
            # inside a multi-line value: count brackets, do not parse
            depth += stripped.count("[") + stripped.count("{")
            depth -= stripped.count("]") + stripped.count("}")
            continue

        line = raw.split("#", 1)[0].rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == "}":
            if len(stack) > 1:
                stack.pop()
            continue
        opened = _OPEN.match(stripped)
        if opened:
            block = {"type": opened.group(1), "kind": opened.group(2) or "",
                     "name": opened.group(3) or "", "attributes": {}, "blocks": [],
                     "raw": [], "line": number}
            stack[-1]["blocks"].append(block)
            stack.append(block)
            continue
        attribute = _ATTRIBUTE.match(stripped)
        if attribute:
            value = attribute.group(2)
            stack[-1]["attributes"][attribute.group(1)] = value
            balance = value.count("[") + value.count("{") - value.count("]") - value.count("}")
            if balance > 0:
                depth = balance
            continue

    for block in _walk(root):
        block.pop("_heredoc_key", None)
    return root


def _walk(block):
    yield block
    for child in block["blocks"]:
        yield from _walk(child)


def _resources(root, kind: str):
    return [b for b in _walk(root) if b["type"] == "resource" and b["kind"] == kind]


def _literal(value: str):
    """The string a Terraform literal holds, or None if it is not a literal.

    None is the important return: a value built from a variable cannot be read here,
    and saying so is better than reading it as empty and reporting nothing.
    """
    value = (value or "").strip()
    if value.startswith('"') and value.endswith('"') and "${" not in value:
        return value[1:-1]
    if value.startswith("[") or value.startswith("{"):
        return value
    if value in ("true", "false") or re.fullmatch(r"-?\d+(?:\.\d+)?", value):
        return value
    return None


def assess_terraform(policy, text: str, target: str = "main.tf") -> list:
    findings = []
    root = parse_blocks(text)

    # --- security group and firewall rules open to the world --------------
    for block in _walk(root):
        if block["type"] != "resource":
            continue
        if "security_group" not in block["kind"] and "firewall" not in block["kind"]:
            continue
        where = "%s: %s.%s" % (target, block["kind"], block["name"])
        for rule in block["blocks"]:
            if rule["type"] not in ("ingress", "egress"):
                continue
            cidrs = rule["attributes"].get("cidr_blocks", "")
            from_port = rule["attributes"].get("from_port")
            to_port = rule["attributes"].get("to_port")
            open_to_world = "0.0.0.0/0" in cidrs or "::/0" in cidrs
            if not open_to_world:
                continue
            if rule["type"] == "egress":
                continue
            exposed = []
            for port in (from_port, to_port):
                literal = _literal(port) if port else None
                if literal is not None and str(literal).isdigit():
                    exposed.append(int(literal))
            if not exposed:
                # A rule whose ports come from a variable cannot be read here.
                evidence = Evidence()
                evidence.add("rule", where,
                             "ingress from %s with from_port=%s to_port=%s"
                             % (cidrs, from_port, to_port))
                evidence.add("observation",
                             "the ports are not literals, so this rule was not evaluated",
                             "")
                findings.append(make(
                    policy.by_id("no-exposed-management-port"), ENVIRONMENT, target,
                    "An ingress rule accepts traffic from any address and its port range "
                    "cannot be read here, so whether it publishes a management interface "
                    "is unknown rather than clear.", evidence, location=where))
                continue
            if any(port in MANAGEMENT_PORTS for port in exposed):
                evidence = Evidence()
                evidence.add("rule", where, "ingress %s from %s" % (exposed, cidrs))
                findings.append(make(
                    policy.by_id("no-exposed-management-port"), ENVIRONMENT, target,
                    "An ingress rule publishes a management port to every address on the "
                    "internet. The exposure is the finding, whatever the credential is.",
                    evidence, location=where))

    # --- identities with a wildcard --------------------------------------
    for block in _walk(root):
        if block["type"] not in ("resource", "data"):
            continue
        if "iam_policy" not in block["kind"] and "iam_role_policy" not in block["kind"] \
                and "policy" != block["kind"]:
            continue
        where = "%s: %s.%s" % (target, block["kind"], block["name"])
        document = block["attributes"].get("policy") or ""
        for candidate in _walk(block):
            document = document or candidate["attributes"].get("policy", "")
        if not document:
            continue
        actions = re.findall(r'"Action"\s*:\s*(\[[^\]]*\]|"[^"]*")', document)
        resources = re.findall(r'"Resource"\s*:\s*(\[[^\]]*\]|"[^"]*")', document)
        wildcard = any('"*"' in group for group in actions + resources)
        if wildcard:
            evidence = Evidence()
            evidence.add("policy", where, (actions + resources)[0][:200] if actions or resources else "")
            findings.append(make(
                policy.by_id("least-privilege-iam"), ENVIRONMENT, target,
                "The policy grants a wildcard action or resource. A wildcard is a "
                "permission nobody had to decide, which is why it survives review.",
                evidence, location=where))

    # --- credentials written into the configuration -----------------------
    for block in _walk(root):
        for name, value in block["attributes"].items():
            if not _SECRET_KEY.search(name):
                continue
            literal = _literal(value)
            if literal is None or _PLACEHOLDER.match(str(value).strip()):
                continue
            if not isinstance(literal, str) or len(literal) < 4:
                continue
            where = "%s: %s.%s" % (target, block.get("kind") or block["type"],
                                   block.get("name") or "?")
            evidence = Evidence()
            evidence.add("attribute", "%s %s" % (where, name), "a literal value")
            evidence.add("observation",
                         "the value is not a variable reference, so it is in the file", "")
            findings.append(make(
                policy.by_id("no-secrets-in-configuration"), ENVIRONMENT, target,
                "A credential is written into the configuration as a literal. The state "
                "file keeps it, the repository keeps it, and the history keeps both.",
                evidence, location=where))
            break

    # --- public storage ---------------------------------------------------
    for block in _resources(root, "aws_s3_bucket_public_access_block"):
        if "block_public_acls" in block["attributes"]:
            literal = _literal(block["attributes"]["block_public_acls"])
            if str(literal).lower() == "false":
                where = "%s: %s.%s" % (target, block["kind"], block["name"])
                evidence = Evidence()
                evidence.add("resource", where, "block_public_acls = false")
                findings.append(make(
                    policy.by_id("no-anonymous-access"), ENVIRONMENT, target,
                    "The bucket's public-access block is explicitly disabled, so the "
                    "storage is reachable without a credential.", evidence, location=where))

    # --- container definitions inside the infrastructure -------------------
    for block in _walk(root):
        # The kind is aws_ecs_task_definition, which contains "task_definition" and
        # not "container_definition". Matching the wrong substring meant these checks
        # never ran at all -- the resource was in the tree and nothing looked at it.
        if block["type"] != "resource" or not (
                "task_definition" in block["kind"]
                or "container_definition" in block["kind"]):
            continue
        where = "%s: %s.%s" % (target, block["kind"], block["name"])
        # The container definition is a JSON blob inside the resource, so the
        # attributes to check are the ones in that blob rather than the resource's
        # own. Reading the block's raw text is what makes this possible after the
        # parser has stopped at the resource boundary.
        blob = "\n".join(block.get("raw") or [])
        # Both spellings appear in real files: a jsonencode block is usually JSON,
        # and a hand-written container definition is usually HCL. Matching only the
        # JSON form meant the HCL form produced nothing, so the privileged and
        # floating-tag checks never fired.
        # One pattern for all four spellings that occur: "key": value (JSON),
        # "key" = value (quoted HCL), key = value (plain HCL), and key: value.
        keys = "name|image|privileged|readonlyRootFilesystem|user"
        # The value class excludes a newline as well as the delimiters: without it
        # the capture ran past the end of the line into the next one, so "true"
        # arrived as "true\n      \"" and never compared equal to anything.
        pattern = r'"?\b(%s)\b"?\s*[:=]\s*("?[^\n",}\]]*"?)' % keys
        for name, value in re.findall(pattern, blob):
            block["attributes"].setdefault(name, value.strip().strip('"'))
        if str(block["attributes"].get("privileged", "")).lower() == "true":
            evidence = Evidence()
            evidence.add("resource", where, "privileged = true")
            findings.append(make(
                policy.by_id("no-privileged-container"), ENVIRONMENT, target,
                "The container definition asks for privileged access to the host.",
                evidence, location=where))
        if str(block["attributes"].get("readonlyRootFilesystem", "")).lower() != "true":
            evidence = Evidence()
            evidence.add("resource", where, "readonlyRootFilesystem is not true")
            findings.append(make(
                policy.by_id("read-only-root-filesystem"), ENVIRONMENT, target,
                "The container definition does not make the root filesystem read-only.",
                evidence, location=where))
        image = block["attributes"].get("image")
        if image:
            literal = _literal(image) or ""
            tag = literal.rsplit(":", 1)[1] if ":" in literal.split("/")[-1] else ""
            if tag in ("", "latest"):
                evidence = Evidence()
                evidence.add("resource", where, "image = %s" % image)
                findings.append(make(
                    policy.by_id("no-latest-tag"), ENVIRONMENT, target,
                    "The container image is referenced by a tag that moves.", evidence,
                    location=where))
        if not block["attributes"].get("user"):
            evidence = Evidence()
            evidence.add("resource", where, "no user attribute")
            findings.append(make(
                policy.by_id("no-root-user"), ENVIRONMENT, target,
                "The container definition names no user, so the task runs as the image's "
                "default.", evidence, location=where))
    return findings


def assess_terraform_file(policy, path: str | Path) -> list:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError("no such file: %s" % path)
    return assess_terraform(policy, path.read_text(encoding="utf-8", errors="replace"),
                            target=path.name)
