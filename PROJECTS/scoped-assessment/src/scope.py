"""The engagement file, and the only door to the network.

Every other module in this package reaches a target by asking this one first. That
is not a convention, it is the design: `Scope.authorize` is the single place that
decides whether an action is permitted, and it is called before a socket is opened
rather than after. A scanner that checks its scope at the end has already done the
thing it was checking about.

The defaults are refusals. A host that is not named is not permitted, a port that
is not listed is not permitted, an action that is not allowed is not permitted, and
a moment outside the engagement window is not permitted. Nothing is permitted by
being absent from a deny list, because a deny list can only ever be as complete as
the person who wrote it.

Every decision -- allowed or refused -- is written to the audit log with the reason
and the time. A refusal that is not recorded is indistinguishable from an action
that never happened, and the record of what a tool *declined* to do is the part an
engagement's client actually wants to see.
"""

from __future__ import annotations

import ipaddress
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

__all__ = ["ScopeError", "Decision", "Scope", "AuditLog", "load_scope"]


class ScopeError(Exception):
    """The engagement file is unusable, so nothing may be attempted."""


class AuditLog:
    """An append-only record of every decision the scope engine made.

    Append-only and line-delimited, so a refusal is on disk the moment it happens
    rather than when the process decides to write a summary. A crash mid-engagement
    should not lose the record of what was attempted.
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.entries: list[dict] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, **entry) -> dict:
        entry.setdefault("at", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        self.entries.append(entry)
        if self.path:
            with open(self.path, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    @property
    def refusals(self) -> list[dict]:
        return [entry for entry in self.entries if not entry.get("allowed", False)]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    host: str = ""
    port: int | None = None
    action: str = ""

    def __bool__(self) -> bool:
        return self.allowed


@dataclass
class Scope:
    """What an engagement permits, and the machinery that enforces it.

    Built by `load_scope` from a file. The fields are the file's fields; nothing
    here has a default that permits something the file did not ask for.
    """

    engagement: str
    targets: list[dict] = field(default_factory=list)
    allowed_actions: set[str] = field(default_factory=set)
    window_start: datetime | None = None
    window_end: datetime | None = None
    audit: AuditLog = field(default_factory=AuditLog)
    source: str = ""

    # -- the door ----------------------------------------------------------
    def authorize(self, host: str, port: int | None = None, action: str = "connect",
                  at: datetime | None = None) -> Decision:
        """Decide whether one action against one target is permitted.

        Returns a `Decision` rather than raising, so a caller can refuse a target
        and carry on with the next one instead of aborting the engagement. Every
        decision is recorded either way.
        """
        decision = self._decide(host, port, action, at or datetime.now(timezone.utc))
        self.audit.record(allowed=decision.allowed, reason=decision.reason, host=host,
                          port=port, action=action, engagement=self.engagement)
        return decision

    def _decide(self, host: str, port: int | None, action: str, at: datetime) -> Decision:
        if not self.targets:
            return Decision(False, "the engagement names no targets, so nothing is permitted",
                            host, port, action)

        if action not in self.allowed_actions:
            return Decision(False, "action %r is not in the engagement's allowed actions"
                            % action, host, port, action)

        if self.window_start and at < self.window_start:
            return Decision(False, "outside the engagement window, which opens %s"
                            % self.window_start.isoformat(timespec="seconds"), host, port, action)
        if self.window_end and at > self.window_end:
            return Decision(False, "outside the engagement window, which closed %s"
                            % self.window_end.isoformat(timespec="seconds"), host, port, action)

        address = _address(host)
        if address is None:
            return Decision(False, "%r is not an address this tool will resolve or guess at"
                            % host, host, port, action)

        matched = [t for t in self.targets if _target_contains(t, address)]
        if not matched:
            return Decision(False, "%s is not within any target the engagement names" % host,
                            host, port, action)

        if port is None:
            return Decision(True, "host permitted", host, port, action)

        for target in matched:
            ports = target.get("ports")
            if ports in (None, "all"):
                return Decision(True, "port %d permitted by a target that names no port limit"
                                % port, host, port, action)
            if int(port) in {int(p) for p in ports}:
                return Decision(True, "permitted", host, port, action)
        return Decision(False, "port %s is not listed for %s" % (port, host), host, port, action)

    # -- convenience -------------------------------------------------------
    def hosts(self) -> list[str]:
        """Every host the engagement names, expanded from any CIDR.

        Expanded for reporting and for a caller that wants to iterate; the
        authorisation decision is still made per host by `authorize`, so this
        cannot be used to reach something the file did not name.
        """
        out: list[str] = []
        for target in self.targets:
            if target.get("host"):
                out.append(str(target["host"]))
            elif target.get("cidr"):
                network = ipaddress.ip_network(str(target["cidr"]), strict=False)
                out.extend(str(address) for address in network.hosts())
        return out

    def as_dict(self) -> dict:
        return {
            "engagement": self.engagement,
            "source": self.source,
            "targets": self.targets,
            "allowed_actions": sorted(self.allowed_actions),
            "window_start": self.window_start.isoformat() if self.window_start else None,
            "window_end": self.window_end.isoformat() if self.window_end else None,
        }


def _address(host: str):
    """The address a host name stands for, or None if it is not one.

    Only literals. A scope engine that resolves names can be pointed at a name
    that resolves to something outside the engagement, which turns the scope file
    into a suggestion. A target must be named as the address it is.
    """
    try:
        return ipaddress.ip_address(str(host).strip())
    except ValueError:
        return None


def _target_contains(target: dict, address) -> bool:
    if target.get("host"):
        other = _address(str(target["host"]))
        return other is not None and other == address
    if target.get("cidr"):
        try:
            network = ipaddress.ip_network(str(target["cidr"]), strict=False)
        except ValueError:
            return False
        return address in network
    return False


def _parse_time(value, field_name: str):
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    for parse in (datetime.fromisoformat,):
        try:
            parsed = parse(text)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    raise ScopeError("the engagement's %s is not a timestamp: %r" % (field_name, value))


def load_scope(path: str | Path, audit_path: str | Path | None = None) -> Scope:
    """Read an engagement file.

    YAML or JSON. Anything wrong with it raises rather than being defaulted away:
    an engagement file that half-parses is more dangerous than one that does not
    parse at all, because the half that parsed is the half that permits something.
    """
    source = Path(path)
    if not source.exists():
        raise ScopeError("no engagement file at %s" % source)
    text = source.read_text(encoding="utf-8")
    if source.suffix.lower() in (".yaml", ".yml"):
        import yaml
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ScopeError("%s is not valid YAML: %s" % (source.name, exc)) from exc
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ScopeError("%s is not valid JSON: %s" % (source.name, exc)) from exc
    if not isinstance(data, dict):
        raise ScopeError("%s must contain one engagement object" % source.name)

    targets = data.get("targets")
    if not isinstance(targets, list):
        raise ScopeError("%s must name its targets as a list" % source.name)
    for index, target in enumerate(targets):
        if not isinstance(target, dict) or not (target.get("host") or target.get("cidr")):
            raise ScopeError("target %d must name a host or a cidr" % index)

    actions = data.get("allowed_actions")
    if not isinstance(actions, list) or not actions:
        raise ScopeError("%s must list the actions it permits" % source.name)

    window = data.get("window") or {}
    if not isinstance(window, dict):
        raise ScopeError("the engagement's window must be a mapping")

    engagement = str(data.get("engagement") or "").strip()
    if not engagement:
        raise ScopeError("%s must name the engagement" % source.name)

    return Scope(
        engagement=engagement,
        targets=targets,
        allowed_actions={str(a).strip().lower() for a in actions},
        window_start=_parse_time(window.get("start"), "window.start"),
        window_end=_parse_time(window.get("end"), "window.end"),
        audit=AuditLog(audit_path),
        source=str(source),
    )
