"""The command line: the policy in, a register out.

One run covers all four environments, because the point of a single policy is that it
is checked against all of them together. An assessment that only looked at
containers would produce a register with no IoT entries and no way to tell that from
an IoT estate that is clean -- which is why the report leads with what was checked
rather than with what was found.

Nothing is defaulted that would change the conclusion. The policy defaults to the one
this repository ships, because that is the organisation's policy and there is exactly
one of it; every artifact has to be named, because an assessor that guessed at which
files to read would be assessing something nobody asked about.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import report as report_module
from .container import assess_container
from .iac import assess_terraform_file
from .iot import assess_broker, assess_device, load_inventory, MQTT_PORT
from .kubernetes import assess_kubernetes_file
from .policy import DEFAULT_POLICY_PATH, PolicyError, load_policy
from .risk import build_register, summarise

__all__ = ["main", "run_assessment"]


def run_assessment(policy_path=None, dockerfiles=(), composes=(), manifests=(),
                   terraform=(), inventory=None, brokers=(), out_dir="posture-output",
                   try_default_credentials=True) -> dict:
    """Assess every named artifact against one policy and write the register."""
    policy = load_policy(policy_path or DEFAULT_POLICY_PATH)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    findings = []
    sources = []

    for path in list(dockerfiles) + list(composes):
        findings.extend(assess_container(policy, path))
        sources.append({"target": Path(path).name, "kind": "container artifact",
                        "path": str(path)})

    for path in manifests:
        findings.extend(assess_kubernetes_file(policy, path))
        sources.append({"target": Path(path).name, "kind": "kubernetes manifest",
                        "path": str(path)})

    for path in terraform:
        findings.extend(assess_terraform_file(policy, path))
        sources.append({"target": Path(path).name, "kind": "terraform",
                        "path": str(path)})

    if inventory:
        devices = load_inventory(inventory)
        for index, device in enumerate(devices):
            findings.extend(assess_device(policy, device,
                                          target="%s[%d]" % (Path(inventory).name, index)))
        sources.append({"target": Path(inventory).name, "kind": "device inventory",
                        "path": str(inventory), "devices": len(devices)})

    for broker in brokers:
        host, _, port = str(broker).partition(":")
        findings.extend(assess_broker(policy, host, int(port or MQTT_PORT),
                                      try_defaults=try_default_credentials))
        sources.append({"target": str(broker), "kind": "mqtt broker"})

    entries = build_register(policy, findings)
    summary = summarise(policy, entries)
    document = report_module.build(policy, entries, summary, sources=sources)

    (out / "register.json").write_text(json.dumps(document, indent=1), encoding="utf-8")
    (out / "report.md").write_text(report_module.to_markdown(document), encoding="utf-8")
    (out / "report.html").write_text(report_module.to_html(document), encoding="utf-8")
    return document


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="posture-assessment",
        description="Check one policy across containers, Kubernetes, infrastructure as "
                    "code and IoT devices.")
    parser.add_argument("--policy", default=None,
                        help="the policy file (default: the one this repository ships)")
    parser.add_argument("--dockerfile", action="append", default=[], metavar="PATH")
    parser.add_argument("--compose", action="append", default=[], metavar="PATH")
    parser.add_argument("--kubernetes", action="append", default=[], metavar="PATH")
    parser.add_argument("--terraform", action="append", default=[], metavar="PATH")
    parser.add_argument("--inventory", default=None, metavar="PATH",
                        help="the organisation's device inventory (JSON)")
    parser.add_argument("--mqtt", action="append", default=[], metavar="HOST[:PORT]",
                        help="a live MQTT broker to assess")
    parser.add_argument("--no-default-credentials", action="store_true",
                        help="skip the published default-credential check")
    parser.add_argument("--out", default="posture-output")
    args = parser.parse_args(argv)

    named = (args.dockerfile or args.compose or args.kubernetes or args.terraform
             or args.inventory or args.mqtt)
    if not named:
        print("nothing was named to assess, so there is nothing to report", file=sys.stderr)
        return 2

    try:
        document = run_assessment(
            policy_path=args.policy, dockerfiles=args.dockerfile, composes=args.compose,
            manifests=args.kubernetes, terraform=args.terraform,
            inventory=args.inventory, brokers=args.mqtt, out_dir=args.out,
            try_default_credentials=not args.no_default_credentials)
    except PolicyError as exc:
        print("the policy is unusable, so nothing was assessed: %s" % exc, file=sys.stderr)
        return 2
    except (FileNotFoundError, ValueError) as exc:
        print("an artifact could not be read: %s" % exc, file=sys.stderr)
        return 2

    summary = document["summary"]
    print("%s: %d register entr%s from %d controls"
          % (document["organisation"], summary["total"],
             "y" if summary["total"] == 1 else "ies", summary["controls_total"]))
    for name in ("critical", "high", "medium", "low"):
        count = summary["by_severity"].get(name, 0)
        if count:
            print("   %-8s %d" % (name, count))
    print("environments assessed: %s"
          % ", ".join(summary["environments_assessed"]) or "none")
    print("register written to %s" % Path(args.out).resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
