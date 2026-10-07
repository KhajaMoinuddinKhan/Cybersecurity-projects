"""The lab: real artifacts with real flaws, and a real broker.

Everything here is a genuine mistake rather than a contrived one. The Dockerfile has
no USER instruction because that is what most Dockerfiles look like; the compose file
sets network_mode: host because that is what somebody does when a container needs to
reach something on the host; the Terraform publishes port 22 to 0.0.0.0/0 because
that is what a rule written at three in the morning looks like.

`lab.json` records what is in here and which control each flaw is meant to violate.
The assessor is never told any of it -- the tests read it, so that a fixture which
stops exercising a control fails rather than passing quietly.
"""

from __future__ import annotations

import json
from pathlib import Path

from .broker import Broker

__all__ = ["Broker", "LAB", "artifacts", "manifest", "LAB_DIR"]

LAB_DIR = Path(__file__).resolve().parent
LAB = LAB_DIR


def manifest() -> dict:
    """What the lab declares it contains, for the tests to check against."""
    return json.loads((LAB_DIR / "lab.json").read_text(encoding="utf-8"))


def artifacts() -> dict:
    """Every artifact in the lab, by name, with its contents."""
    out = {}
    for path in sorted(LAB_DIR.iterdir()):
        if path.suffix in (".yaml", ".yml", ".tf", ".json") and path.name != "lab.json" \
                or path.name.startswith("Dockerfile"):
            out[path.name] = path.read_text(encoding="utf-8", errors="replace")
    return out
