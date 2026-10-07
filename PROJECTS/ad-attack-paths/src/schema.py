"""The collector's data model, read as it is written.

SharpHound writes one JSON file per object type, each shaped
``{"meta": {...}, "data": [...]}``, and an object carries its own properties, the
access control entries that grant *other* principals rights over it, its group
memberships if it is a group, and its sessions if it is a computer.

The direction of an access control entry is the thing worth stating plainly,
because it is the opposite of how it reads. An entry sits on the object it
protects, and names the principal that holds the right: an entry on a user saying
``PrincipalSID: <Domain Admins>, RightName: GenericAll`` means Domain Admins can do
anything to that user. An attacker who controls the principal therefore reaches the
object, so the traversal runs principal to object -- and a reader who takes the
entry at face value will build the graph backwards.

Nothing here decides what is dangerous. This module reads the data and normalises
it; the meaning of a right lives in `rights.py` and the judgement about what counts
as a crown jewel lives in `tier0.py`.
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["CollectorError", "Ace", "Node", "CollectorData", "load_collector",
           "load_forest", "OBJECT_FILES", "SUPPORTED_VERSIONS"]

# The file names the collector writes, and the node kind each one carries. A file
# that is not in this table is not ignored by accident -- see `load_collector`.
OBJECT_FILES = {
    "users": "user",
    "groups": "group",
    "computers": "computer",
    "domains": "domain",
    "ous": "ou",
    "gpos": "gpo",
    "containers": "container",
    "rootcas": "rootca",
    "aiacas": "aiaca",
    "enterprisecas": "enterpriseca",
    "ntauthstores": "ntauthstore",
    "certtemplates": "certtemplate",
}

# The collector format version this reads. Version 6 is what SharpHound 2.x writes;
# a different version is refused rather than half-understood.
SUPPORTED_VERSIONS = (6,)


class CollectorError(ValueError):
    """The archive is not collector output this can read, and says why."""


@dataclass(frozen=True)
class Ace:
    """One right, held by one principal, over the object it is stored on."""

    principal_sid: str
    principal_type: str
    right: str
    inherited: bool = False

    def as_dict(self) -> dict:
        return {"principal": self.principal_sid, "principal_type": self.principal_type,
                "right": self.right, "inherited": self.inherited}


@dataclass
class Node:
    """One object in the directory, with everything the collector said about it."""

    sid: str
    kind: str
    name: str = ""
    domain: str = ""
    properties: dict = field(default_factory=dict)
    # rights other principals hold over this object
    aces: list = field(default_factory=list)
    # who is in this group
    members: list = field(default_factory=list)
    # who has a session on this computer. The collector nests these under a
    # `Results` key inside a collection record, so reading the field as a list
    # silently yields nothing at all -- which is what happened first.
    sessions: list = field(default_factory=list)
    privileged_sessions: list = field(default_factory=list)
    registry_sessions: list = field(default_factory=list)
    trusts: list = field(default_factory=list)
    # containers and organisational units are keyed by GUID while accounts and
    # groups are keyed by SID, so this may not match any node -- and often does not,
    # because the collector only collects some containers.
    contained_by: str = ""
    child_objects: list = field(default_factory=list)
    links: list = field(default_factory=list)
    # Local group membership per machine, and the rights held on it. Both are
    # collected per machine and often refused, so an empty list is a fact about the
    # collection rather than about the machine.
    local_groups: list = field(default_factory=list)
    user_rights: list = field(default_factory=list)
    is_dc: bool = False
    # which policy applies to this container, and which container a policy is linked to
    links: list = field(default_factory=list)
    # where this account's service principal name is hosted
    spn_targets: list = field(default_factory=list)
    # The primary group is how a directory expresses membership that does not appear
    # in the member list. A domain controller is a member of Domain Controllers this
    # way, so reading only the member list is reading membership that may not be there.
    primary_group: str = ""
    # certificate services. The authority is hosted on a machine, holds security
    # descriptors of its own, and has templates enabled on it.
    # what a policy changes on the machines it applies to, and the domain controller's
    # own registry data. Both are parsed so that a populated one is used rather than
    # silently dropped.
    gpo_changes: dict = field(default_factory=dict)
    dc_registry: dict = field(default_factory=dict)
    hosting_computer: str = ""
    ca_security: list = field(default_factory=list)
    cert_templates: list = field(default_factory=list)
    primary_group: str = ""
    sid_history: list = field(default_factory=list)
    spn_targets: list = field(default_factory=list)
    allowed_to_delegate: list = field(default_factory=list)
    allowed_to_act: list = field(default_factory=list)
    source_file: str = ""

    @property
    def enabled(self) -> bool:
        """Whether the object is usable. Absent means yes: a domain or a group has
        no enabled flag and is not therefore disabled."""
        value = self.properties.get("enabled")
        return True if value is None else bool(value)

    @property
    def admin_count(self) -> bool:
        """The flag the directory sets on an object placed in a protected group."""
        return bool(self.properties.get("admincount"))

    @property
    def domain_sid(self) -> str:
        return str(self.properties.get("domainsid") or "")

    @property
    def rid(self) -> str:
        """The last component of the SID, which is what distinguishes the
        well-known accounts from the rest without matching on a name."""
        return self.sid.rsplit("-", 1)[-1] if self.sid else ""

    def as_dict(self) -> dict:
        return {"sid": self.sid, "kind": self.kind, "name": self.name,
                "domain": self.domain, "admincount": self.admin_count,
                "enabled": self.enabled}


@dataclass
class CollectorData:
    """Every object from one collection run, and where it came from."""

    nodes: dict = field(default_factory=dict)          # sid -> Node
    source: str = ""
    domains: tuple = ()
    version: int = 0
    counts: dict = field(default_factory=dict)

    def by_kind(self, kind: str) -> list:
        return [node for node in self.nodes.values() if node.kind == kind]

    def get(self, sid: str) -> Node | None:
        return self.nodes.get(sid)

    def summary(self) -> dict:
        return {"source": self.source, "version": self.version,
                "objects": len(self.nodes), "by_kind": dict(self.counts),
                "domains": list(self.domains)}


def _collection(entry, key: str) -> list:
    """The entries inside one of the collector's collection records.

    Sessions, privileged sessions and registry sessions are each written as
    ``{"Results": [...], "Collected": bool, "FailureReason": ...}``. A reader that
    treats the field as a list of sessions gets an empty result and no error, so the
    shape is unpacked here once rather than at every call site.
    """
    value = entry.get(key)
    if isinstance(value, dict):
        return list(value.get("Results") or [])
    if isinstance(value, list):
        return list(value)
    return []


def _identifier(entry, key: str) -> str:
    """The identifier out of a reference, which the collector writes as a mapping.

    `ContainedBy` is `{"ObjectIdentifier": ..., "ObjectType": ...}` rather than a
    bare string, and reading it as a string produces an empty parent for every
    object in the directory.
    """
    value = entry.get(key)
    if isinstance(value, dict):
        return str(value.get("ObjectIdentifier") or "")
    return str(value or "")


def _read_json(handle, name: str) -> dict:
    try:
        raw = json.loads(handle.read(name).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectorError("%s is not valid JSON: %s" % (name, exc)) from exc
    if not isinstance(raw, dict) or "data" not in raw:
        raise CollectorError("%s is not collector output: it has no `data` key" % name)
    return raw


def _kind_of(filename: str) -> str | None:
    """Which object type a file carries, from its name.

    The collector prefixes every file with the domain and a timestamp, so the type
    is matched on the stem rather than on the whole name.
    """
    stem = Path(filename).stem.lower()
    for key, kind in OBJECT_FILES.items():
        if stem == key or stem.endswith("_" + key):
            return kind
    return None


def load_forest(paths) -> CollectorData:
    """Read several collections into one directory.

    A forest is not one domain. Trusts run between domains, a compromise in one is a
    route into another, and an analysis that reads a single archive reports the trust
    as an unresolved reference -- which is what the first run of this did. Each
    archive is read separately and the objects merged, so an object that appears in
    two collections is one node rather than two.
    """
    if isinstance(paths, (str, Path)):
        paths = [paths]
    merged = CollectorData()
    sources = []
    for path in paths:
        part = load_collector(path)
        sources.append(str(path))
        for sid, node in part.nodes.items():
            merged.nodes.setdefault(sid, node)
        merged.version = part.version or merged.version
    if not merged.nodes:
        raise CollectorError("no objects were read from any of %s" % ", ".join(sources))
    merged.source = "; ".join(sources)
    merged.counts = {}
    for node in merged.nodes.values():
        merged.counts[node.kind] = merged.counts.get(node.kind, 0) + 1
    merged.domains = tuple(sorted({node.name for node in merged.by_kind("domain") if node.name}))
    return merged


def load_collector(path: str | Path) -> CollectorData:
    """Read a collector archive or a directory of its JSON files."""
    path = Path(path)
    if not path.exists():
        raise CollectorError("no such archive or directory: %s" % path)

    if path.is_dir():
        entries = {p.name: p.read_bytes() for p in sorted(path.iterdir())
                   if p.suffix.lower() == ".json"}
        names = sorted(entries)
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            names = [n for n in archive.namelist()
                     if n.lower().endswith(".json") and not n.startswith("__MACOSX")]
            entries = {n: archive.read(n) for n in names}
    else:
        raise CollectorError("%s is neither a zip archive nor a directory" % path)

    data = CollectorData(source=str(path))
    unrecognised = []
    for name in names:
        kind = _kind_of(name)
        if kind is None:
            unrecognised.append(Path(name).name)
            continue
        raw = _read_json(_BytesReader(entries[name]), name)
        meta = raw.get("meta") or {}
        version = meta.get("version")
        if version not in SUPPORTED_VERSIONS:
            raise CollectorError(
                "%s declares collector format version %r; this reads %s. A different "
                "version is refused rather than half-understood."
                % (Path(name).name, version, ", ".join(str(v) for v in SUPPORTED_VERSIONS)))
        data.version = version
        for entry in raw.get("data") or []:
            node = _build_node(entry, kind, Path(name).name)
            if node is not None:
                data.nodes[node.sid] = node

    if not data.nodes:
        raise CollectorError(
            "no objects were read from %s. Recognised file types are %s; the archive "
            "held %s."
            % (path, ", ".join(sorted(OBJECT_FILES)), ", ".join(unrecognised) or "nothing"))

    data.counts = {}
    for node in data.nodes.values():
        data.counts[node.kind] = data.counts.get(node.kind, 0) + 1
    data.domains = tuple(sorted({node.name for node in data.by_kind("domain") if node.name}))
    return data


class _BytesReader:
    """The slice of a file object `_read_json` needs, over bytes already in memory."""

    def __init__(self, payload: bytes):
        self.payload = payload

    def read(self, _name: str = "") -> bytes:
        return self.payload


def _session_sid(session) -> str:
    """The user a session belongs to, whichever way the collector spelled it."""
    if isinstance(session, str):
        return session
    if isinstance(session, dict):
        return str(session.get("UserSID") or session.get("ObjectIdentifier") or "")
    return ""


def _build_node(entry: dict, kind: str, source_file: str) -> Node | None:
    sid = str(entry.get("ObjectIdentifier") or "").strip()
    if not sid:
        return None                     # an object with no SID cannot be joined to anything
    properties = entry.get("Properties") or {}
    return Node(
        sid=sid,
        kind=kind,
        name=str(properties.get("name") or "").strip(),
        domain=str(properties.get("domain") or "").strip().upper(),
        properties=properties,
        aces=[Ace(principal_sid=str(ace.get("PrincipalSID") or ""),
                  principal_type=str(ace.get("PrincipalType") or ""),
                  right=str(ace.get("RightName") or ""),
                  inherited=bool(ace.get("IsInherited")))
              for ace in (entry.get("Aces") or []) if ace.get("PrincipalSID")],
        # Members arrive as objects in one collector's output and as bare identifiers
        # in another's. Everywhere else in this file both shapes are accepted; here the
        # dict was assumed, and a collection with plain strings ended the analysis with
        # an AttributeError before anything was reported.
        members=[_identifier({"m": m}, "m") for m in (entry.get("Members") or [])
                 if _identifier({"m": m}, "m")],
        sessions=[sid for sid in (_session_sid(s) for s in _collection(entry, "Sessions"))
                  if sid],
        privileged_sessions=[sid for sid in
                             (_session_sid(s) for s in _collection(entry, "PrivilegedSessions"))
                             if sid],
        registry_sessions=[sid for sid in
                           (_session_sid(s) for s in _collection(entry, "RegistrySessions"))
                           if sid],
        trusts=list(entry.get("Trusts") or []),
        contained_by=_identifier(entry, "ContainedBy"),
        child_objects=[_identifier({"x": c}, "x") for c in (entry.get("ChildObjects") or [])],
        links=list(entry.get("Links") or []),
        local_groups=[g for g in (entry.get("LocalGroups") or []) if isinstance(g, dict)],
        user_rights=[r for r in (entry.get("UserRights") or []) if isinstance(r, dict)],
        is_dc=bool(entry.get("IsDC")),
        primary_group=str(entry.get("PrimaryGroupSID") or ""),
        sid_history=[str(s.get("ObjectIdentifier") or s) if isinstance(s, dict) else str(s)
                     for s in (entry.get("HasSIDHistory") or [])],
        # SPNTargets are objects, not identifiers: each names a computer, a port and
        # the service, and coercing them to strings loses all three.
        spn_targets=[t for t in (entry.get("SPNTargets") or []) if isinstance(t, dict)],
        allowed_to_delegate=[str(s.get("ObjectIdentifier") or s) if isinstance(s, dict) else str(s)
                             for s in (entry.get("AllowedToDelegate") or [])],
        allowed_to_act=[str(s.get("ObjectIdentifier") or s) if isinstance(s, dict) else str(s)
                        for s in (entry.get("AllowedToAct") or [])],
        gpo_changes=dict(entry.get("GPOChanges") or {}),
        dc_registry=dict(entry.get("DCRegistryData") or {}),
        hosting_computer=str(entry.get("HostingComputer") or ""),
        ca_security=[a for a in ((entry.get("CARegistryData") or {}).get("CASecurity", {})
                                 .get("Data") or []) if isinstance(a, dict)],
        cert_templates=[t for t in (entry.get("EnabledCertTemplates") or [])
                        if isinstance(t, dict)],
        source_file=source_file,
    )
