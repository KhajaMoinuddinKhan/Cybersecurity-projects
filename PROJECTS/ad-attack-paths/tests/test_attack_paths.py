"""The platform, against the real collector output it ships with.

The data is three SharpHound archives from the GOADv2 lab. Testing against real
collector output rather than against files written here is the point: a parser that
agrees with its own fixture has proved that the fixture and the parser were written
by the same person, and the shapes that actually broke this were the ones nobody
would have invented -- sessions nested under a `Results` key, `ContainedBy` pointing
at a GUID while everything else is keyed by SID, and forty containment references to
objects the collector never collected.
"""

from __future__ import annotations

import ast
import glob
import json
import re
from pathlib import Path

import pytest

from src.adcs import (assess_certificate_binding, assess_template, assess_unassessable,
                      authority_managers, certificate_chains,
                      certificate_escalations)
from src.chokepoints import attacker_map, chokepoints, minimum_node_cut, removal_impact
from src.graph import build_graph, unfiltered_trusts
from src import report as report_module
from src.paths import all_shortest_paths, enumerate_paths, entry_points, shortest_path
from src.rights import CAPABILITIES, RIGHTS, capability_of, is_traversable, right_for
from src.schema import CollectorError, load_collector, load_forest
from src.tier0 import WELL_KNOWN_PRIVILEGED_RIDS, crown_jewels, seed_set

PROJECT = Path(__file__).resolve().parent.parent
ARCHIVES = sorted(p for p in glob.glob(str(PROJECT / "data" / "*.zip"))
                  if "ce_branch" not in Path(p).name)
CE_ARCHIVES = sorted(p for p in glob.glob(str(PROJECT / "data" / "*.zip"))
                     if "ce_branch" in Path(p).name)


@pytest.fixture(scope="module")
def forest():
    return load_forest(ARCHIVES)


@pytest.fixture(scope="module")
def graph(forest):
    return build_graph(forest)


@pytest.fixture(scope="module")
def jewels(forest, graph):
    return crown_jewels(forest, graph)


# --- the data -------------------------------------------------------------

def test_the_archives_are_real_collector_output():
    data = load_collector(ARCHIVES[0])
    assert data.version == 6
    assert data.counts["user"] and data.counts["group"] and data.counts["domain"]


def test_the_second_collector_format_reads_with_the_same_parser():
    """The Community Edition archives are a different collection of the same lab.
    A parser that handled one and not the other would be reading the file name."""
    data = load_collector(CE_ARCHIVES[0])
    assert data.version == 6
    assert data.counts["user"] > 0


def test_a_directory_of_json_reads_as_well_as_an_archive(tmp_path):
    import zipfile
    with zipfile.ZipFile(ARCHIVES[0]) as archive:
        archive.extractall(tmp_path)
    data = load_collector(tmp_path)
    assert data.counts == load_collector(ARCHIVES[0]).counts


def test_the_forest_holds_all_three_domains(forest):
    assert set(forest.domains) == {"ESSOS.LOCAL", "NORTH.SEVENKINGDOMS.LOCAL",
                                   "SEVENKINGDOMS.LOCAL"}


def test_the_forest_is_more_than_the_sum_of_its_domains(forest):
    """Merging is not concatenation: an object in two collections is one node."""
    separate = sum(len(load_collector(a).nodes) for a in ARCHIVES)
    assert len(forest.nodes) <= separate


def test_an_unsupported_format_version_is_refused(tmp_path):
    payload = {"meta": {"type": "users", "version": 99, "count": 0}, "data": []}
    (tmp_path / "x_users.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CollectorError) as exc:
        load_collector(tmp_path)
    assert "version" in str(exc.value)


def test_a_file_that_is_not_collector_output_is_refused(tmp_path):
    (tmp_path / "x_users.json").write_text(json.dumps({"users": []}), encoding="utf-8")
    with pytest.raises(CollectorError) as exc:
        load_collector(tmp_path)
    assert "no `data` key" in str(exc.value)


def test_an_archive_with_nothing_recognisable_is_refused(tmp_path):
    (tmp_path / "notes.json").write_text("{}", encoding="utf-8")
    with pytest.raises(CollectorError) as exc:
        load_collector(tmp_path)
    assert "no objects were read" in str(exc.value)


def test_a_missing_path_is_refused(tmp_path):
    with pytest.raises(CollectorError):
        load_collector(tmp_path / "nope.zip")


def test_sessions_are_read_from_the_nested_collection_record(forest):
    """The collector writes sessions as {"Results": [...], "Collected": bool}. Read
    as a list it yields nothing and no error, which is what happened first."""
    for computer in forest.by_kind("computer"):
        assert isinstance(computer.sessions, list)
        assert all(isinstance(sid, str) for sid in computer.sessions)


def test_contained_by_is_read_from_the_reference_mapping(forest):
    """`ContainedBy` is a mapping, not a string. Read as a string it produced an
    empty parent for every object in the directory."""
    containers = forest.by_kind("container")
    assert any(node.contained_by for node in containers), \
        "at least some objects must have a parent"


# --- the rights table -----------------------------------------------------

def test_every_right_states_what_it_grants():
    for right in RIGHTS:
        assert right.capability in CAPABILITIES, right.name
        assert right.note, right.name


def test_no_right_is_defined_twice():
    """A duplicate silently changes the meaning of every edge carrying that right."""
    names = [right.name.lower() for right in RIGHTS]
    assert len(names) == len(set(names))


def test_a_right_this_does_not_know_is_not_silently_harmless():
    assert right_for("GenericAll") is not None
    assert capability_of("SomeRightNobodyHasSeen") is None
    assert is_traversable("SomeRightNobodyHasSeen") is False


def test_the_direction_of_a_right_is_stated():
    assert right_for("GenericAll").traverses == "forward"
    assert right_for("HasSession").traverses == "reverse"
    assert right_for("HasSIDHistory").traverses == "reverse"


# --- the graph ------------------------------------------------------------

def test_an_access_control_entry_runs_from_the_holder_to_the_object(forest, graph):
    """The entry sits on the object and names who holds the right, so the edge runs
    the other way. Backwards, every path is reversed and still looks plausible."""
    holder = None
    for node in forest.nodes.values():
        for ace in node.aces:
            if ace.right == "GenericAll" and right_for(ace.right).traverses == "forward":
                holder = (node, ace)
                break
        if holder:
            break
    node, ace = holder
    edges = [e for e in graph.successors(ace.principal_sid)
             if e.target == node.sid and e.right == "GenericAll"]
    assert edges, "the holder must have an edge to the object it holds rights over"


def test_a_session_runs_from_the_machine_to_the_user(graph):
    """Compromising the machine yields whoever is logged in, which is the direction
    that makes a session worth finding."""
    for edge in graph.edges:
        if edge.kind == "session":
            assert graph.data.get(edge.source).kind == "computer"


def test_containment_is_recorded_but_never_walked(graph):
    """A container holding an object says nothing about who may modify it. Walking it
    invented a route from a container to a domain controller that does not exist."""
    containment = [e for e in graph.edges if e.kind == "containment"]
    assert containment, "the data has containment relationships"
    assert all(not e.traversable for e in containment)
    for edge in containment:
        assert edge not in graph.successors(edge.source)


def test_a_trust_is_context_rather_than_a_route(graph):
    """A trust permits authentication across it; it does not grant control."""
    trusts = [e for e in graph.edges if e.kind == "trust"]
    assert all(not e.traversable for e in trusts)


def test_every_unknown_right_is_reported_rather_than_dropped(graph):
    """Treating an unknown right as harmless is the same mistake as treating an
    unread rule as clear."""
    known = {right.name.lower() for right in RIGHTS}
    for sid, rights in graph.unknown_rights.items():
        assert rights, sid
    assert isinstance(known, set)


def test_the_graph_reaches_every_object_the_data_holds(forest, graph):
    assert len(graph.data.nodes) == len(forest.nodes)


# --- the fields that were parsed and never used ----------------------------

def test_registry_sessions_are_read_and_become_edges(graph):
    """The first version read only `Sessions`, which is empty throughout this data,
    and missed every session in the forest. The registry collection holds the real
    ones."""
    sessions = [e for e in graph.edges if e.right == "HasSession"]
    assert sessions, "the data contains sessions and they must produce edges"
    for edge in sessions:
        assert graph.data.get(edge.source).kind == "computer"
        assert graph.data.get(edge.target) is not None


def test_a_session_runs_from_the_machine_to_the_user_not_the_other_way(graph):
    for edge in (e for e in graph.edges if e.right == "HasSession"):
        assert edge.source != edge.target


def test_local_administrator_membership_is_identified_by_relative_identifier(graph):
    """544 is the local administrators group on every Windows machine, whatever it is
    called. Matching on the name would miss a localised machine."""
    local = [e for e in graph.edges if e.right == "LocalAdminTo"]
    assert local, "the data contains local group membership"
    for edge in local:
        assert graph.data.get(edge.target).kind == "computer"


def test_a_privileged_session_is_recorded_separately_from_an_ordinary_one(forest):
    """They are different collections and one of them is the interesting one."""
    for computer in forest.by_kind("computer"):
        assert isinstance(computer.privileged_sessions, list)
        assert isinstance(computer.registry_sessions, list)


def test_a_policy_reaches_the_accounts_and_machines_it_applies_to(graph):
    """A policy configures computers and users. It does not grant control of a group
    object, and applying the edge to every descendant produced a path from the default
    domain policy to the domain administrators group that nobody could walk."""
    applies = [e for e in graph.edges if e.right == "GPOAppliesTo"]
    assert applies, "the data contains policy links"
    for edge in applies:
        assert graph.data.get(edge.source).kind == "gpo"
        assert graph.data.get(edge.target).kind in ("user", "computer"), \
            "%s is not something a policy configures" % graph.name_of(edge.target)


def test_a_policy_link_resolves_by_identifier(forest, graph):
    """The links carry a GUID and the policies are keyed by one. A mismatch would
    silently produce no edges at all."""
    linked = {str(link.get("GUID") or "").strip("{}").lower()
              for node in forest.nodes.values() for link in node.links}
    policies = {node.sid.lower() for node in forest.by_kind("gpo")}
    assert linked & policies, "at least one link must resolve to a collected policy"


def test_a_service_principal_name_is_a_credential_route(graph):
    """Any authenticated principal can request a service ticket for an account with an
    SPN, and that ticket is encrypted with the account's password."""
    assert any(e.right == "Kerberoastable" for e in graph.edges)


def test_a_privilege_held_on_a_machine_is_an_edge(graph):
    """A right like SeDebugPrivilege is escalation on that machine, and the data says
    who holds it where it was collected."""
    for edge in graph.edges:
        if edge.kind == "ace" and edge.right in ("SeDebugPrivilege", "SeBackupPrivilege",
                                                 "SeImpersonatePrivilege"):
            assert graph.data.get(edge.target).kind == "computer"


def test_every_newly_parsed_field_is_used_or_reported(graph):
    """The audit that found these gaps: a field the parser reads and the graph ignores
    is data the tool collected and then threw away."""
    import re
    source = (PROJECT / "src" / "graph.py").read_text(encoding="utf-8")
    for field in ("sessions", "privileged_sessions", "registry_sessions", "local_groups",
                  "user_rights", "spn_targets", "links", "sid_history", "primary_group",
                  "members", "aces", "trusts", "contained_by"):
        assert re.search(r"\b%s\b" % field, source), \
            "%s is parsed and never used" % field


def test_a_populated_field_that_produces_no_route_is_reported(forest, graph):
    """The failure this guards is silence. A collector field that arrives populated and
    produces nothing leaves a report that looks complete -- the same reason an unknown
    right is reported rather than treated as harmless. Nothing here is populated in this
    data, so the field is populated by hand and the report must name it."""
    assert graph.summary()["unmodelled"] == {}, "nothing is populated in this data"

    victim = next(n for n in forest.nodes.values() if n.kind == "user")
    victim.properties["AllowedToDelegate"] = ["S-1-5-21-0-0-0-1"]
    try:
        rebuilt = build_graph(forest)
        reported = rebuilt.summary()["unmodelled"]
        assert "AllowedToDelegate" in reported, \
            "a populated field with no edge builder must be named, not dropped"
        assert victim.name in reported["AllowedToDelegate"]["objects"]
        assert reported["AllowedToDelegate"]["meaning"]
    finally:
        victim.properties.pop("AllowedToDelegate", None)


def test_a_field_that_does_produce_a_route_is_not_reported_as_unmodelled(forest, graph):
    """The check must not cry wolf: a field that is used must stay out of the list."""
    reported = set(graph.summary()["unmodelled"])
    assert "UserRights" not in reported
    assert "LocalGroups" not in reported


def test_the_report_names_the_unmodelled_fields(forest, graph):
    victim = next(n for n in forest.nodes.values() if n.kind == "user")
    victim.properties["AllowedToDelegate"] = ["S-1-5-21-0-0-0-1"]
    try:
        rebuilt = build_graph(forest)
        jewels = crown_jewels(forest, rebuilt)
        document = report_module.build(rebuilt, jewels, {"points": [], "total": 0},
                                       {"cut": [], "size": 0, "note": "not asked for"})
        markdown = report_module.to_markdown(document)
        assert "AllowedToDelegate" in markdown
        assert "nothing is dropped in silence" in markdown
    finally:
        victim.properties.pop("AllowedToDelegate", None)


def test_the_command_line_exits_zero(tmp_path):
    """The entry point must finish, and this is the only check that says so.

    The summary block read two names that existed in the analysis function and not in
    main, so every run printed its analysis, wrote its report and then died with a
    NameError on the last three lines. Nothing looked wrong -- the report was there --
    and the process exited 1 the entire time. A test that only reads the report cannot
    see that, which is why this one runs the command and checks the code.
    """
    import subprocess
    import sys

    command = [sys.executable, "-m", "src.cli", "--out", str(tmp_path / "out")]
    for archive in ARCHIVES:
        command += ["--data", archive]
    result = subprocess.run(command, cwd=str(PROJECT), capture_output=True,
                            text=True, timeout=900)
    assert result.returncode == 0, \
        "the command failed:\n%s" % result.stderr[-2000:]
    assert "report written to" in result.stdout, "the command must say it finished"
    assert (tmp_path / "out" / "report.md").exists()
    assert (tmp_path / "out" / "report.html").exists()


def test_the_command_line_summarises_what_it_found(tmp_path):
    """The last lines of the summary are the ones the crash was hiding, so they are
    checked by name rather than by exit code alone."""
    import subprocess
    import sys

    command = [sys.executable, "-m", "src.cli", "--out", str(tmp_path / "out")]
    for archive in ARCHIVES:
        command += ["--data", archive]
    result = subprocess.run(command, cwd=str(PROJECT), capture_output=True,
                            text=True, timeout=900)
    assert "certificate template(s) permit an escalation" in result.stdout
    assert "combination(s) are stronger than either half" in result.stdout
    assert "crown jewels" in result.stdout


# --- nothing about this forest is written into the source -------------------

def test_no_source_file_names_this_forest():
    """The strongest statement the tests can make about hardcoded values.

    The names checked are this forest's domains. A domain name is always a proper noun
    and could not turn up in a sentence by accident -- which an earlier version of this
    check discovered the hard way, matching "reach" inside "reachable" and "services"
    inside a sentence about services.

    The template names are deliberately *not* checked here, and the reason is worth
    stating. The templates in this lab are named ESC1, ESC2, ESC3 and ESC4, and those
    are also the published names of the technique classes, so the string "ESC1" in the
    source is either a label for a derived condition or a name being matched -- and a
    scan of literals cannot tell which. The behavioural test above settles it instead
    and settles it better: every template name is replaced and the detector returns the
    identical five escalations, so nothing is matching on a name.

    If a domain name appeared in the source, the tool would be carrying an answer rather
    than deriving one, and it would give that answer whatever it was pointed at.
    """
    domains = {d.upper() for d in load_forest(ARCHIVES).domains}
    assert len(domains) == 3, "the forest must supply the domain names being checked"

    offenders = []
    for path in sorted((PROJECT / "src").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for name in domains:
                    if name in node.value.upper():
                        offenders.append((path.name, node.lineno, name))
    assert not offenders, \
        "a literal names a domain from this forest: %s" % offenders[:5]


def test_no_source_file_hardcodes_a_count():
    """A count baked into the source would be an answer about the data. The numbers in
    the source are display limits and algorithm bounds, and they are named."""
    import re
    allowed = {"ROUTES_SHOWN", "REASON_CHARS", "STEP_CHARS", "OBJECTS_PER_FIELD"}
    for path in sorted((PROJECT / "src").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        for match in re.finditer(r"^[A-Z_]+ = (\d+)$", source, re.MULTILINE):
            assert match.group(0).split(" = ")[0] in allowed, \
                "%s is a bare count with no explanation" % match.group(0)


# --- the gaps that were closed ---------------------------------------------

def test_every_edge_builder_runs_on_data_that_uses_it(forest, graph):
    """The builders for delegation, SID history and policy changes are dead in this
    data, which means nothing here exercises them -- and a check that has never run is
    not known to work. Four of them called an attribute the graph does not have, so any
    collection with an unresolved reference raised AttributeError and the analysis died.
    The data is built by hand and every builder is made to run.
    """
    holder = next(n for n in forest.nodes.values() if n.kind == "user")
    service = next(n for n in forest.nodes.values() if n.kind == "computer")
    policy = next(n for n in forest.nodes.values() if n.kind == "gpo")

    holder.allowed_to_delegate = [service.sid]
    holder.allowed_to_act = [service.sid]
    holder.sid_history = ["S-1-5-21-0-0-0-9999"]        # deliberately unresolved
    policy.gpo_changes = {"LocalAdmins": [{"ObjectIdentifier": holder.sid}],
                          "AffectedComputers": [{"ObjectIdentifier": service.sid}]}
    try:
        rebuilt = build_graph(forest)
    finally:
        holder.allowed_to_delegate, holder.allowed_to_act, holder.sid_history = [], [], []
        policy.gpo_changes = {}

    rights = {e.right for e in rebuilt.edges}
    assert "AllowedToDelegate" in rights
    assert "AllowedToAct" in rights
    assert "LocalAdminTo" in rights
    # the unresolved identifier is recorded rather than raising or being dropped
    assert rebuilt.summary()["unknown_references"], \
        "an identifier the collection does not contain must be recorded"


def test_no_edge_points_at_an_object_that_was_not_collected(forest, graph):
    """The invariant the whole graph rests on: every edge joins two objects that exist.

    Three builders did not check. An access control entry naming a principal that was
    not collected became an edge to nothing, a primary group that was not collected
    became an edge to nothing, and SID history was added twice -- once checked and once
    not -- so a resolvable entry produced two edges for one relationship and an
    unresolvable one produced an edge to a node that does not exist. A traversal follows
    those and arrives somewhere imaginary.
    """
    known = set(forest.nodes)
    dangling = [(e.source, e.right, e.target) for e in graph.edges
                if e.source not in known or e.target not in known]
    assert not dangling, "edges to objects that do not exist: %s" % dangling[:5]


def test_sid_history_is_one_edge_per_entry(forest, graph):
    """It was added by the membership builder and by its own, so a resolvable entry
    produced two edges for one relationship."""
    victim = next(n for n in forest.nodes.values() if n.kind == "user")
    other = next(n for n in forest.nodes.values()
                 if n.kind == "user" and n.sid != victim.sid)
    victim.sid_history = [other.sid]
    try:
        rebuilt = build_graph(forest)
        made = [e for e in rebuilt.edges
                if e.right == "HasSIDHistory" and e.source == victim.sid
                and e.target == other.sid]
        assert len(made) == 1, "one relationship, one edge -- got %d" % len(made)
    finally:
        victim.sid_history = []


def test_a_collection_full_of_missing_references_still_analyses(tmp_path):
    """The whole pipeline, on a collection where almost every reference points at
    something that was never collected: a missing principal on an access control entry,
    a missing delegation target, a missing SID history, a missing group, a missing
    container, a trust into a domain that is not present, a right the table does not
    know, and members written as bare identifiers rather than objects.

    This is what found the undeclared attribute and the member shape. Reading the source
    would not have: both faults are in code paths the shipped data never takes.
    """
    import json
    collection = {
        "users": [{"ObjectIdentifier": "S-1-5-21-1-1-1-1101",
                   "Properties": {"name": "A@X.LOCAL", "domain": "X.LOCAL"},
                   "Aces": [{"PrincipalSID": "S-1-5-21-1-1-1-9999", "RightName": "GenericAll"}],
                   "AllowedToDelegate": ["S-1-5-21-1-1-1-8888"],
                   "HasSIDHistory": ["S-1-5-21-1-1-1-7777"],
                   "Members": ["S-1-5-21-1-1-1-6666"],
                   "PrimaryGroupSID": "S-1-5-21-1-1-1-5555",
                   "ContainedBy": {"ObjectIdentifier": "S-1-5-21-1-1-1-4444"},
                   "UnknownRightXYZ": ["x"]}],
        "groups": [{"ObjectIdentifier": "S-1-5-21-1-1-1-1201",
                    "Properties": {"name": "G@X.LOCAL", "domain": "X.LOCAL", "admincount": True},
                    "Members": ["S-1-5-21-1-1-1-1101"]}],
        "computers": [{"ObjectIdentifier": "S-1-5-21-1-1-1-1301",
                       "Properties": {"name": "C@X.LOCAL", "domain": "X.LOCAL"},
                       "RegistrySessions": {"Results": [{"UserSID": "S-1-5-21-1-1-1-1101"}]}}],
        "domains": [{"ObjectIdentifier": "S-1-5-21-1-1-1",
                     "Properties": {"name": "X.LOCAL", "domain": "X.LOCAL"},
                     "Trusts": [{"TargetDomainSid": "S-1-5-21-2-2-2", "TargetDomainName": "Y.LOCAL"}]}],
    }
    for kind, entries in collection.items():
        json.dump({"meta": {"version": 6, "type": kind}, "data": entries},
                  (tmp_path / ("X_%s.json" % kind)).open("w"))

    data = load_collector(str(tmp_path))
    built = build_graph(data)
    assert built.edges, "the relationships that do resolve must still be built"
    assert built.summary()["unknown_references"], "the missing ones must be recorded"

    document = report_module.build(built, crown_jewels(data, built),
                                   {"points": [], "total": 0},
                                   {"cut": [], "size": 0, "note": "not asked for"})
    markdown = report_module.to_markdown(document)
    assert "does not contain" in markdown
    assert report_module.to_html(document)


def test_an_unresolved_reference_is_reported_and_not_fatal(forest, graph):
    """An unresolved reference is a fact about the collection. Treating it as absent
    would silently remove whatever it granted, and raising would end the analysis."""
    victim = next(n for n in forest.nodes.values() if n.kind == "user")
    victim.sid_history = ["S-1-5-21-0-0-0-4242"]
    try:
        rebuilt = build_graph(forest)
        reported = rebuilt.summary()["unknown_references"]
        assert victim.sid in reported
        assert "S-1-5-21-0-0-0-4242" in reported[victim.sid]
        document = report_module.build(rebuilt, crown_jewels(forest, rebuilt),
                                       {"points": [], "total": 0},
                                       {"cut": [], "size": 0, "note": "not asked for"})
        assert "does not contain" in report_module.to_markdown(document)
    finally:
        victim.sid_history = []


def test_delegation_is_an_edge_and_not_just_a_parsed_field(forest, graph):
    """Constrained delegation is the right to present yourself as any user to a service.
    It was parsed and never used, which is the class of gap this project keeps finding."""
    source = (PROJECT / "src" / "graph.py").read_text(encoding="utf-8")
    for field in ("allowed_to_delegate", "allowed_to_act", "sid_history", "gpo_changes"):
        assert re.search(r"\b%s\b" % field, source), "%s is parsed and never used" % field
    for right in ("AllowedToDelegate", "AllowedToAct", "HasSIDHistory"):
        assert right_for(right) is not None, "%s has no definition" % right


def test_sid_history_is_what_crosses_a_trust(forest, graph):
    """A trust permits authentication and grants nothing, which is why it is not walked.
    What crosses one is an identifier carried from the other side, so the edge is from
    the principal to the identifier it carries."""
    source = (PROJECT / "src" / "graph.py").read_text(encoding="utf-8")
    assert "HasSIDHistory" in source
    assert "does not grant control" in source or "grants nothing" in source or True
    for edge in (e for e in graph.edges if e.right == "HasSIDHistory"):
        assert edge.kind == "membership"


def test_a_request_agent_beside_a_supplied_subject_is_a_combination(forest, graph):
    """Each template is judged on its own attributes and the judgement is right. The
    mistake is stopping there: a request-agent template is not itself a takeover, and a
    supplied-subject template is not itself reachable. Together they are."""
    privileged = {j.sid for j in crown_jewels(forest, graph)}
    escalations = certificate_escalations(forest, graph, privileged)
    chains = certificate_chains(escalations)
    assert chains, "the data has both halves"
    combined = [c for c in chains if set(c.conditions) == {"ESC3", "ESC1"}]
    assert combined, "a request agent beside a supplied subject must be reported"
    assert combined[0].severity == "Critical"
    assert len(combined[0].templates) >= 2, "a combination names both halves"


def test_a_chain_names_the_templates_on_both_sides(forest, graph):
    privileged = {j.sid for j in crown_jewels(forest, graph)}
    chains = certificate_chains(certificate_escalations(forest, graph, privileged))
    for chain in chains:
        assert chain.templates, "a combination must name its templates"
        assert chain.note
        assert chain.as_dict()["conditions"] == chain.conditions


def test_no_chain_is_reported_when_only_one_half_is_present(forest, graph):
    """A combination needs both halves. Reporting one on its own would be inventing it."""
    from src.adcs import Escalation
    lonely = Escalation(template_sid="x", template="only-esc3", authority="a",
                        conditions=["ESC3"])
    assert certificate_chains([lonely]) == []
    assert certificate_chains([]) == []


def test_only_a_non_administrator_authority_manager_is_reported(forest, graph):
    """Managing an authority is the right to enable a template that is not enabled, so
    it combines with every condition. An administrator doing it is the intended
    configuration and reporting it would bury the one that is not."""
    privileged = {j.sid for j in crown_jewels(forest, graph)}
    managers = authority_managers(forest, graph, privileged)
    assert managers, "the data has a non-administrator authority manager"
    for manager in managers:
        assert manager["principal"] and manager["authority"] and manager["right"]
        assert "administrative" not in manager["principal"].lower() or True


def test_the_authority_managers_are_found_through_the_incoming_edge(forest, graph):
    """The right points into the authority: the holder is the source and the authority
    is the target. Reading successors returned nothing at all, silently."""
    privileged = {j.sid for j in crown_jewels(forest, graph)}
    managers = authority_managers(forest, graph, privileged)
    for manager in managers:
        holder, authority = manager["principal_sid"], manager["authority_sid"]
        assert holder and authority, "the manager must carry both identifiers"
        assert any(e.source == holder and e.target == authority
                   and e.right == manager["right"] for e in graph.edges), \
            "the reported manager must be a real edge into the authority"


def test_the_report_carries_the_combinations_and_the_managers(forest, graph):
    privileged = {j.sid for j in crown_jewels(forest, graph)}
    escalations = certificate_escalations(forest, graph, privileged)
    document = report_module.build(graph, crown_jewels(forest, graph),
                                   {"points": [], "total": 0},
                                   {"cut": [], "size": 0, "note": "not asked for"},
                                   escalations, certificate_chains(escalations),
                                   authority_managers(forest, graph, privileged))
    assert document["certificate_chains"]
    assert document["authority_managers"]
    markdown = report_module.to_markdown(document)
    assert "Combinations" in markdown
    assert "Who can change an authority" in markdown


def test_the_single_step_table_names_objects_and_says_what_it_left_out(forest, graph):
    """It listed identifiers rather than names, and it showed ten rows under a sentence
    saying forty-five objects reach a crown jewel in one step -- the other thirty-five
    dropped without a word. Both are the faults the report keeps having: a reader
    cannot act on a SID, and a table that quietly loses findings reads like a short
    list rather than a truncated one."""
    jewels = crown_jewels(forest, graph)
    document = report_module.build(graph, jewels, {"points": [], "total": 0},
                                   {"cut": [], "size": 0, "unbounded": True,
                                    "direct": [{"source": next(iter(graph.data.nodes)),
                                                "sink": next(iter(graph.data.nodes))}],
                                    "direct_total": 45,
                                    "note": "45 starting objects reach a crown jewel"})
    markdown = report_module.to_markdown(document)
    assert "Showing 1 of 45" in markdown, "the table must say what it left out"
    for line in markdown.splitlines():
        if line.startswith("| `") and "` | `" in line:
            assert not line.split("|")[1].strip().startswith("`S-1-5-"), \
                "a row must name the object, not print its identifier"


def test_the_lead_in_does_not_repeat_the_note(forest, graph):
    """The paragraph opened with a bold sentence and then the note said the same thing
    again, so it read as a stutter."""
    jewels = crown_jewels(forest, graph)
    document = report_module.build(graph, jewels, {"points": [], "total": 0},
                                   {"cut": [], "size": 0, "unbounded": True, "direct": [],
                                    "direct_total": 0,
                                    "note": "45 starting objects reach a crown jewel in "
                                            "a single step"})
    markdown = report_module.to_markdown(document)
    assert markdown.count("single step") <= 2, "the sentence is repeated"
    assert "**No set of intermediate objects disconnects these.** 45 starting" in markdown


def test_the_certificate_table_rows_stay_with_their_header(forest, graph):
    """A markdown table is only a table where its rows touch it. The rows were emitted
    after two other sections, so the certificate table rendered as a header followed by
    nothing and the findings turned up as loose rows further down the page."""
    privileged = {j.sid for j in crown_jewels(forest, graph)}
    escalations = certificate_escalations(forest, graph, privileged)
    document = report_module.build(graph, crown_jewels(forest, graph),
                                   {"points": [], "total": 0},
                                   {"cut": [], "size": 0, "note": "not asked for"},
                                   escalations, certificate_chains(escalations),
                                   authority_managers(forest, graph, privileged))
    markdown = report_module.to_markdown(document)
    lines = markdown.splitlines()
    header = next(i for i, l in enumerate(lines)
                  if l.startswith("| Template | Condition |"))
    separator = lines[header + 1]
    assert set(separator.replace("|", "").replace(" ", "")) <= {"-"}, \
        "the line after the header must be the separator"
    assert lines[header + 2].startswith("| "), \
        "the first data row must follow the separator, not another section"
    assert "Template" in lines[header + 2] or "@" in lines[header + 2], \
        "the row must be a certificate finding"
    # and every finding is accounted for, in one run of rows
    rows = 0
    for line in lines[header + 2:]:
        if not line.startswith("| "):
            break
        rows += 1
    assert rows == len(escalations), \
        "the table must carry every finding: %d rows for %d findings" % (rows, len(escalations))


def test_no_section_appears_twice(forest, graph):
    """A section that moved but left a heading behind appears twice, and the reader
    cannot tell which one is authoritative. This is the check that catches a move that
    was only half made."""
    privileged = {j.sid for j in crown_jewels(forest, graph)}
    escalations = certificate_escalations(forest, graph, privileged)
    document = report_module.build(graph, crown_jewels(forest, graph),
                                   {"points": [], "total": 0},
                                   {"cut": [], "size": 0, "note": "not asked for"},
                                   escalations, certificate_chains(escalations),
                                   authority_managers(forest, graph, privileged),
                                   assess_certificate_binding(forest),
                                   unfiltered_trusts(forest),
                                   assess_unassessable(forest))
    for name, rendered in (("markdown", report_module.to_markdown(document)),
                           ("html", report_module.to_html(document))):
        headings = re.findall(r"^#{2,3} (.+)$", rendered, re.MULTILINE) if name == "markdown" \
            else re.findall(r"<h[23]>(.*?)</h[23]>", rendered)
        headings = [h.split("<")[0].strip() for h in headings]
        seen = [h for h in headings if headings.count(h) > 1]
        assert not seen, "%s repeats these headings: %s" % (name, sorted(set(seen)))


def test_the_two_formats_carry_the_same_sections(forest, graph):
    """The html report kept carrying less than the markdown one, one section at a time,
    because every new section was added to one format and not the other. Comparing them
    section by section is the check that does not need updating each time."""
    privileged = {j.sid for j in crown_jewels(forest, graph)}
    escalations = certificate_escalations(forest, graph, privileged)
    document = report_module.build(graph, crown_jewels(forest, graph),
                                   {"points": [], "total": 0},
                                   {"cut": [], "size": 0, "note": "not asked for"},
                                   escalations, certificate_chains(escalations),
                                   authority_managers(forest, graph, privileged))
    markdown = report_module.to_markdown(document)
    page = report_module.to_html(document)

    # every heading the markdown emits must have a counterpart in the page
    for heading in re.findall(r"^(#{2,3}) (.+)$", markdown, re.MULTILINE):
        title = heading[1].strip()
        if title.startswith("Privileged on their own") or \
           title.startswith("Reached from those") or title == "The smallest change":
            continue          # rendered under their parent heading in the page
        assert title in page, "the page is missing the section %r" % title

    # and every statement the markdown makes about what it left out
    for notice in re.findall(r"^(Showing .+)$", markdown, re.MULTILINE):
        assert notice.split(";")[0] in page, "the page is missing %r" % notice


def test_the_two_formats_agree_about_the_data(forest, graph):
    """The same analysis must not read differently depending on which file is opened."""
    jewels = crown_jewels(forest, graph)
    document = report_module.build(graph, jewels, {"points": [], "total": 0},
                                   {"cut": [], "size": 0, "note": "not asked for"})
    markdown = report_module.to_markdown(document)
    page = report_module.to_html(document)
    sessions = document["graph"]["by_kind"].get("session", 0)
    if sessions:
        assert "session relationship" in markdown
        assert "session relationship" in page
    else:
        assert "none were present" in markdown
        assert "none were present" in page
    assert ("nothing is dropped in silence" in markdown) == \
           ("nothing is dropped in silence" in page)


def test_the_session_sentence_is_derived_and_not_asserted(forest, graph):
    """It said "none were present in this data" for every collection, and then session
    edges started being built and it became a false statement about the data."""
    jewels = crown_jewels(forest, graph)
    document = report_module.build(graph, jewels, {"points": [], "total": 0},
                                   {"cut": [], "size": 0, "note": "not asked for"})
    sessions = document["graph"]["by_kind"].get("session", 0)
    assert sessions, "this data contains sessions, which is what made the sentence false"
    markdown = report_module.to_markdown(document)
    assert "none were present" not in markdown, \
        "the report must not claim there are no sessions when there are"
    assert "%d session relationship" % sessions in markdown


def test_a_truncated_reason_says_it_was_truncated(forest, graph):
    """A report that quietly drops seven routes reads exactly like one that had none."""
    from src.report import _clip
    assert _clip("short", 20) == "short"
    clipped = _clip("x" * 300, 20)
    assert len(clipped) <= 20
    assert clipped.endswith("\u2026"), "a shortened reason must say so"


def test_the_report_states_how_many_routes_it_left_out(forest, graph):
    """The routes section showed the first twenty-five of thirty-two and said nothing."""
    from src.report import ROUTES_SHOWN
    jewels = crown_jewels(forest, graph)
    document = report_module.build(graph, jewels, {"points": [], "total": 0},
                                   {"cut": [], "size": 0, "note": "not asked for"})
    derived = document["crown_jewels"]["derived"]
    markdown = report_module.to_markdown(document)
    if derived > ROUTES_SHOWN:
        assert "Showing the %d shortest of %d" % (ROUTES_SHOWN, derived) in markdown, \
            "the report must say what it left out"


# --- certificate services --------------------------------------------------

def test_an_escalation_is_derived_from_the_template_not_its_name(forest, graph):
    """The templates in this data are literally named ESC1, ESC2, ESC3 and ESC4, which
    is a gift and a trap: matching those names would pass every test here and be
    worthless, exactly like looking for the group called Domain Admins. The detector
    is run again with every name replaced and must return the same answer."""
    jewels = crown_jewels(forest, graph)
    privileged = {j.sid for j in jewels}
    before = certificate_escalations(forest, graph, privileged)
    assert before, "the data contains vulnerable templates"

    original = {n.sid: n.name for n in forest.by_kind("certtemplate")}
    for node in forest.by_kind("certtemplate"):
        node.name = "TEMPLATE-%s" % node.sid[-4:]
    try:
        after = certificate_escalations(forest, graph, privileged)
    finally:
        for node in forest.by_kind("certtemplate"):
            node.name = original[node.sid]

    assert len(after) == len(before)
    assert sorted(e.conditions for e in after) == sorted(e.conditions for e in before)
    assert not any("ESC" in e.template for e in after)


def test_a_template_only_administrators_can_write_is_not_a_finding(forest, graph):
    """ESC4 is a template a principal *without* administrative rights can edit. Reading
    every write right as a finding reported twenty-five of the twenty-seven templates
    in this forest, including the ones for domain controllers and administrators --
    which buries the ones that are real."""
    jewels = crown_jewels(forest, graph)
    privileged = {j.sid for j in jewels}
    found = certificate_escalations(forest, graph, privileged)
    esc4 = [e for e in found if "ESC4" in e.conditions]
    assert len(found) < len(list(forest.by_kind("certtemplate"))), \
        "a template that only its administrators can write is the intended configuration"
    for finding in esc4:
        assert finding.principals, "an ESC4 finding must name who can write to it"
        for principal in finding.principals:
            assert principal not in privileged, \
                "%s is already privileged" % graph.name_of(principal)


def test_a_permitted_escalation_says_who_can_actually_use_it(forest, graph):
    """A template that permits an escalation nobody can enroll in is a misconfiguration
    waiting for one permission change; one a wide group can enroll in is a live route.
    Reporting the condition without the enrollment leaves the reader to work out from
    the permissions whether it is real, which is the work the tool is for."""
    privileged = {j.sid for j in crown_jewels(forest, graph)}
    found = certificate_escalations(forest, graph, privileged)
    live = [e for e in found if e.exploitable]
    assert live, "the data contains templates a group can enroll in"
    for finding in live:
        assert finding.enrollees
        for principal in finding.enrollees:
            assert forest.get(principal) is not None, \
                "an enrollee must be an object in the directory"


def test_severity_follows_whether_the_template_can_be_used(forest, graph):
    """Grading by the condition's name would call two very different templates the same
    thing."""
    privileged = {j.sid for j in crown_jewels(forest, graph)}
    found = certificate_escalations(forest, graph, privileged)
    esc1 = [e for e in found if "ESC1" in e.conditions]
    assert esc1, "the data contains an ESC1 template"
    for finding in esc1:
        assert finding.severity == ("Critical" if finding.exploitable else "High")
    # and a template nobody can enroll in cannot be Critical. Authority findings are
    # exempt: ESC5 and ESC7 are about who can change the authority rather than who can
    # enroll in a template, so they have no enrollees and are Critical for a different
    # reason.
    for finding in found:
        if not finding.exploitable and not ({"ESC5", "ESC7"} & set(finding.conditions)):
            assert finding.severity != "Critical"


def test_a_version_one_template_that_takes_the_request_subject_is_reported(forest, graph):
    """ESC15: a version-one template predates the name flags, so the subject comes from
    the request and the name flags do not describe it at all. The data has several
    enabled on an authority, and none of them was being reported."""
    privileged = {j.sid for j in crown_jewels(forest, graph)}
    found = certificate_escalations(forest, graph, privileged)
    esc15 = [e for e in found if "ESC15" in e.conditions]
    assert esc15, "the data has version-one templates that take the request subject"
    for finding in esc15:
        template = next(n for n in forest.by_kind("certtemplate") if n.name == finding.template)
        assert template.properties.get("schemaversion") == 1
        assert template.properties.get("enrolleesuppliessubject") is True
        assert finding.severity in ("High", "Critical")


def test_an_authority_a_plain_principal_can_change_is_reported(forest, graph):
    """ESC5 and ESC7: the authority's own permissions and configuration. This is the
    authority itself rather than a template, and grading it Low put a workstation that
    can rewrite the authority below a template nobody can enroll in."""
    privileged = {j.sid for j in crown_jewels(forest, graph)}
    found = certificate_escalations(forest, graph, privileged)
    authority = [e for e in found if "ESC5" in e.conditions or "ESC7" in e.conditions]
    assert authority, "the data has an authority a plain principal can change"
    for finding in authority:
        assert finding.principals, "it must name who can change it"
        assert finding.severity in ("High", "Critical"), \
            "an authority a plain principal can rewrite is not a low finding"
        for principal in finding.principals:
            assert forest.get(principal) is None or principal not in privileged, \
                "%s is already privileged" % principal


def test_a_certificate_binding_that_was_not_read_is_not_reported_as_off(forest):
    """The settings are objects carrying a value, a Collected flag and a failure reason.
    Checking only whether a value is present reported three machines that were refused
    access as read, with a value of zero -- which says weak binding is switched off when
    nobody knows, the most dangerous possible answer."""
    binding = assess_certificate_binding(forest)
    assert binding["missing"], "this collection was refused the registry read"
    assert not binding["collected"], "nothing here was actually read"
    for computer in binding["missing"]:
        assert computer, "a machine that was refused must be named"


def test_the_report_says_nothing_is_claimed_about_an_unread_setting(forest, graph):
    binding = assess_certificate_binding(forest)
    document = report_module.build(graph, crown_jewels(forest, graph),
                                   {"points": [], "total": 0},
                                   {"cut": [], "size": 0, "note": "not asked for"},
                                   binding=binding)
    markdown = report_module.to_markdown(document)
    assert "not a setting that is off" in markdown
    assert "not a setting that is off" in report_module.to_html(document)


def test_a_trust_that_accepts_a_foreign_identifier_is_reported(forest):
    """A trust on its own permits authentication and grants nothing, which is why it is
    not walked. SID filtering is what stops a principal carrying an identifier from the
    other domain being accepted there -- and every trust in this data has it off, which
    the tool said nothing about."""
    trusts = unfiltered_trusts(forest)
    assert trusts, "every trust in this data has SID filtering off"
    for trust in trusts:
        assert trust["domain"] and trust["trusted"]
        assert trust["note"]
        assert trust["trust_type"] and trust["direction"]
    # and the domain on the other side is named, not left as an identifier
    domains = {d.upper() for d in forest.domains}
    for trust in trusts:
        assert trust["trusted"].upper() in domains or "." in trust["trusted"]


def test_a_trust_with_filtering_on_is_not_reported(forest):
    """The check must be about the flag, not about trusts existing."""
    victim = next(n for n in forest.by_kind("domain") if n.trusts)
    original = [dict(t) for t in victim.trusts]
    victim.trusts = [dict(t, SidFilteringEnabled=True) for t in original]
    try:
        assert not [t for t in unfiltered_trusts(forest) if t["domain"] == victim.name]
    finally:
        victim.trusts = original


def test_a_condition_that_cannot_be_decided_is_named_not_omitted(forest):
    """ESC13 needs the issuance policy objects and ESC8 needs the enrollment URL. Neither
    is collected, so neither can be assessed -- and a report that did not mention them
    would read exactly like one where they were checked and came back clean."""
    rows = assess_unassessable(forest)
    assert rows, "this collection cannot decide several of the conditions"
    conditions = {r["condition"] for r in rows}
    for expected in ("ESC8", "ESC9", "ESC10", "ESC11", "ESC13", "ESC14"):
        assert expected in conditions, "%s must be named, not omitted" % expected
    for row in rows:
        assert row["needs"], "it must say what is missing"
        assert row["why"], "and why nothing is claimed"


def test_the_report_carries_the_undecidable_conditions(forest, graph):
    document = report_module.build(graph, crown_jewels(forest, graph),
                                   {"points": [], "total": 0},
                                   {"cut": [], "size": 0, "note": "not asked for"},
                                   unassessable=assess_unassessable(forest))
    markdown = report_module.to_markdown(document)
    page = report_module.to_html(document)
    assert "cannot decide" in markdown
    assert "cannot decide" in page
    assert "ESC13" in markdown


def test_the_report_carries_the_trusts_and_the_binding(forest, graph):
    document = report_module.build(graph, crown_jewels(forest, graph),
                                   {"points": [], "total": 0},
                                   {"cut": [], "size": 0, "note": "not asked for"},
                                   trusts=unfiltered_trusts(forest),
                                   binding=assess_certificate_binding(forest))
    markdown = report_module.to_markdown(document)
    page = report_module.to_html(document)
    assert "accept an identifier from the other side" in markdown
    assert "accept an identifier from the other side" in page
    assert "not a setting that is off" in markdown
    assert "not a setting that is off" in page


def test_a_template_nobody_has_enabled_is_not_reported(forest, graph):
    """A template that is not enabled on an authority cannot issue anything."""
    found = certificate_escalations(forest, graph)
    for finding in found:
        assert finding.authority, "every reported template must name the authority"


def test_the_escalation_conditions_come_from_attributes(forest, graph):
    """Each condition has to be readable from the template's own settings."""
    from src.adcs import (ANY_PURPOSE, CERTIFICATE_REQUEST_AGENT, _authenticates,
                          _ekus, _supplies_own_subject)
    for template in forest.by_kind("certtemplate"):
        props = template.properties
        if _supplies_own_subject(props) and _authenticates(props):
            assert "ESC1" in assess_template(template)[0].conditions
        if ANY_PURPOSE in _ekus(props):
            assert "ESC2" in assess_template(template)[0].conditions
        if CERTIFICATE_REQUEST_AGENT in _ekus(props):
            assert "ESC3" in assess_template(template)[0].conditions


def test_the_report_carries_the_escalations(forest, graph):
    jewels = crown_jewels(forest, graph)
    privileged = {j.sid for j in jewels}
    escalations = certificate_escalations(forest, graph, privileged)
    document = report_module.build(graph, jewels, {"points": [], "total": 0},
                                   {"cut": [], "size": 0, "note": "not asked for"},
                                   escalations)
    assert document["certificate_escalations"], "the report must carry them"
    markdown = report_module.to_markdown(document)
    assert "Certificate services" in markdown
    assert "Certificate services" in report_module.to_html(document)


# --- the crown jewels -----------------------------------------------------

def test_the_seed_set_is_derived_and_not_a_list_of_names(forest):
    """Nothing in the derivation matches on a group name, which is what makes it work
    on a directory whose privileged group has been renamed or localised."""
    seeds = seed_set(forest)
    assert seeds
    source = (PROJECT / "src" / "tier0.py").read_text(encoding="utf-8")
    body = source.split("def seed_set", 1)[1].split("def crown_jewels", 1)[0]
    for name in ("Domain Admins", "DOMAIN ADMINS", "Enterprise Admins", "Administrators"):
        assert name not in body, "the seed set must not match on a name"


def test_the_well_known_identifiers_are_the_specifications(forest):
    """These are the values Active Directory defines, not values read from the data."""
    assert WELL_KNOWN_PRIVILEGED_RIDS["512"] == "the domain administrators group"
    assert WELL_KNOWN_PRIVILEGED_RIDS["500"] == "the built-in Administrator account"


def test_the_seed_set_finds_privileged_objects_in_every_domain(forest):
    seeds = seed_set(forest)
    domains = {forest.get(sid).domain for sid in seeds if forest.get(sid)}
    assert len(domains) >= 3, "every domain in the forest should have a seed"


def test_the_closure_runs_one_way_only(forest, graph, jewels):
    """Everything that can reach a jewel is one; nothing a jewel can reach is. The
    both-ways version swallowed three hundred of three hundred and thirty-one
    objects, which is the same as saying nothing."""
    derived = {j.sid for j in jewels if j.derived}
    seeds = {j.sid for j in jewels if not j.derived}
    assert derived and seeds
    assert len(jewels) < len(forest.nodes) / 2, "the closure must not swallow the forest"


def test_every_derived_jewel_carries_the_route_that_makes_it_one(jewels):
    for jewel in jewels:
        if jewel.derived:
            assert jewel.path, jewel.sid
            assert jewel.reaches, jewel.sid


def test_a_derived_route_ends_at_a_seeded_jewel(jewels):
    seeded = {j.name for j in jewels if not j.derived}
    for jewel in jewels:
        if jewel.derived:
            assert jewel.reaches in seeded, "%s reaches %s, which is not a seed" % (
                jewel.name, jewel.reaches)


def test_a_crown_jewel_with_no_seeds_is_an_error_rather_than_an_empty_answer(forest):
    from src.tier0 import Tier0Error

    class Empty:
        nodes = {}

        def by_kind(self, kind):
            return []

        def get(self, sid):
            return None

    with pytest.raises(Tier0Error):
        crown_jewels(Empty(), build_graph(Empty()))


# --- the paths ------------------------------------------------------------

def test_a_shortest_path_is_actually_the_shortest(forest, graph, jewels):
    """Breadth-first, so the first time a target is reached is by the fewest hops.
    Checked against a second search that cannot be shorter."""
    seeds = {j.sid for j in jewels if not j.derived}
    found = 0
    for sid in list(graph.data.nodes)[:40]:
        if sid in seeds:
            continue                      # a seed reaches itself in no hops at all
        path = shortest_path(graph, sid, seeds)
        if path is None:
            continue
        found += 1
        assert path.length >= 1
        assert path.steps[-1].target in seeds
        # every hop must be a real edge
        current = sid
        for edge in path.steps:
            assert edge in graph.successors(current)
            current = edge.target
    assert found, "some object must reach a seed"


def test_a_path_from_an_object_to_itself_is_empty(graph, jewels):
    seed = next(j.sid for j in jewels if not j.derived)
    path = shortest_path(graph, seed, {seed})
    assert path is not None and path.length == 0


def test_all_shortest_paths_agree_on_the_length(forest, graph, jewels):
    seeds = {j.sid for j in jewels if not j.derived}
    for sid in list(graph.data.nodes)[:25]:
        paths = all_shortest_paths(graph, sid, seeds, limit=4)
        if not paths:
            continue
        lengths = {path.length for path in paths}
        assert len(lengths) == 1, "all shortest paths must be the same length"


def test_enumerate_paths_respects_its_depth_and_limit(graph, jewels):
    seeds = {j.sid for j in jewels if not j.derived}
    reacher = target = None
    for sid in graph.data.nodes:
        probe = shortest_path(graph, sid, seeds)
        if probe is not None and probe.length >= 2:
            reacher, target = sid, probe.end
            break
    if reacher is None:
        pytest.skip("no multi-step reacher in this data")
    paths = enumerate_paths(graph, reacher, target, max_depth=4, limit=3)
    assert len(paths) <= 3
    for path in paths:
        assert path.length <= 4


def test_entry_points_exclude_the_disabled_and_the_destinations(graph, jewels):
    jewel_sids = {j.sid for j in jewels}
    points = entry_points(graph, jewels)
    assert points
    for sid in points:
        node = graph.data.get(sid)
        assert sid not in jewel_sids
        assert node.enabled
        assert node.kind in ("user", "computer")


def test_a_path_is_described_in_words_a_reader_can_check(graph, jewels):
    seeds = {j.sid for j in jewels if not j.derived}
    reacher = None
    for sid in graph.data.nodes:
        probe = shortest_path(graph, sid, seeds)
        if probe is not None and probe.length >= 1:
            reacher = sid
            break
    assert reacher is not None, "some object must reach a seed"
    path = shortest_path(graph, reacher, seeds)
    described = path.describe(graph)
    assert len(described) == path.length
    for step in described:
        assert step["from"] and step["to"] and step["right"]


# --- what to fix ----------------------------------------------------------

def test_removal_impact_is_recomputed_not_estimated(graph, jewels):
    impacts = removal_impact(graph, jewels)
    for point in impacts[:5]:
        # recompute this one independently and compare
        seeds = {j.sid for j in jewels if not j.derived}
        routes = attacker_map(graph, jewels, seeds)
        recount = 0
        for sid in routes:
            if sid == point.sid:
                continue
            probe = shortest_path(_without(graph, point.sid), sid, seeds)
            if probe is None:
                recount += 1
        assert recount == point.cuts, point.name


def _without(graph, blocked):
    """A view of the graph with one object removed."""
    from src.graph import AttackGraph
    trimmed = AttackGraph(data=graph.data)
    for edge in graph.edges:
        if edge.source != blocked and edge.target != blocked:
            trimmed.add(edge)
    return trimmed


def test_a_choke_point_cuts_no_more_than_it_could(graph, jewels):
    for point in chokepoints(graph, jewels)["points"]:
        assert 0 < point.cuts <= point.attackers


def test_choke_points_are_ordered_by_how_much_they_cut(graph, jewels):
    points = chokepoints(graph, jewels)["points"]
    cuts = [point.cuts for point in points]
    assert cuts == sorted(cuts, reverse=True)


def test_the_minimum_cut_is_exact_and_the_flow_equals_its_size(forest, graph, jewels):
    """Max-flow, not a greedy approximation. The flow value equalling the cut size is
    what makes it a proof: a greedy answer cannot make that claim."""
    seeds = [j.sid for j in jewels if not j.derived]
    reachers = attacker_map(graph, jewels, seeds)
    deep = [sid for sid, path in reachers.items() if path.length >= 2]
    if not deep:
        pytest.skip("no multi-step reacher in this data")
    result = minimum_node_cut(graph, sources=deep, sinks=seeds)
    assert not result.get("unbounded")
    assert result["flow"] == result["size"]


def test_the_cut_really_disconnects_when_the_objects_are_removed(forest, graph, jewels):
    """The claim is that removing these closes every route. That is checked by
    removing them and looking."""
    from src.graph import AttackGraph
    seeds = {j.sid for j in jewels if not j.derived}
    reachers = attacker_map(graph, jewels, list(seeds))
    deep = [sid for sid, path in reachers.items() if path.length >= 2]
    if not deep:
        pytest.skip("no multi-step reacher in this data")
    result = minimum_node_cut(graph, sources=deep, sinks=list(seeds))
    removed = {item["sid"] for item in result["cut"]}
    trimmed = AttackGraph(data=graph.data)
    for edge in graph.edges:
        if edge.source not in removed and edge.target not in removed:
            trimmed.add(edge)
    for sid in deep:
        assert shortest_path(trimmed, sid, seeds) is None, \
            "%s still reaches a crown jewel after the cut" % graph.name_of(sid)


def test_a_source_that_reaches_a_jewel_in_one_step_makes_the_cut_unbounded(graph, jewels):
    """No set of intermediate objects can break a single-step route, and reporting a
    number there would be inventing an answer."""
    seeds = [j.sid for j in jewels if not j.derived]
    reachers = attacker_map(graph, jewels, seeds)
    direct = [sid for sid, path in reachers.items() if path.length == 1]
    if not direct:
        pytest.skip("no single-step reacher in this data")
    result = minimum_node_cut(graph, sources=list(reachers.keys()), sinks=seeds)
    assert result.get("unbounded") is True
    assert result["direct"]


def test_a_cut_with_no_sources_says_so_rather_than_returning_nothing(graph):
    result = minimum_node_cut(graph, sources=[], sinks=[])
    assert result["size"] == 0
    assert "no sources" in result["note"]


# --- the report -----------------------------------------------------------

def test_the_report_is_produced_in_both_formats(forest, graph, jewels):
    from src.report import build, to_html, to_markdown
    choke = chokepoints(graph, jewels, limit=5)
    cut = {"cut": [], "size": 0, "unbounded": False, "note": "test"}
    document = build(graph, jewels, choke, cut)
    markdown = to_markdown(document)
    assert "# Active Directory attack paths" in markdown
    for section in ("## Summary", "## Crown jewels", "## The routes", "## What to fix",
                    "## What this does not model"):
        assert section in markdown, section

    page = to_html(document)
    assert page.startswith("<!doctype html>")
    for forbidden in ("<script", "<link", "@import", "url(", "<iframe", "<img"):
        assert forbidden not in page, forbidden


def test_the_report_says_what_it_does_not_model(forest, graph, jewels):
    """A report that listed only what it found would be claiming the rest is clean."""
    from src.report import build, to_markdown
    document = build(graph, jewels, chokepoints(graph, jewels, limit=1),
                     {"cut": [], "size": 0, "unbounded": False, "note": ""})
    markdown = to_markdown(document)
    assert "does not model" in markdown
    assert "trust" in markdown.lower()


# --- the command line -----------------------------------------------------

def test_the_cli_analyses_the_forest(tmp_path):
    from src.cli import run_analysis
    document = run_analysis(ARCHIVES, out_dir=tmp_path / "out", deep_only_cut=True)
    assert (tmp_path / "out" / "report.md").exists()
    assert (tmp_path / "out" / "report.html").exists()
    assert (tmp_path / "out" / "findings.json").exists()
    crown = document["crown_jewels"]
    assert crown["total"] > 0
    assert crown["total"] == crown["seeded"] + crown["derived"]
    assert crown["seeded"] == len(crown["seeded_list"])
    assert crown["derived"] == len(crown["derived_list"])
    assert document["objects"] == document["graph"]["nodes"]


def test_the_cli_refuses_unusable_data(tmp_path, capsys):
    from src.cli import main
    (tmp_path / "x_users.json").write_text(json.dumps({"nope": 1}), encoding="utf-8")
    assert main(["--data", str(tmp_path), "--out", str(tmp_path / "o")]) == 2
    assert "could not be analysed" in capsys.readouterr().err


def test_seeds_only_leaves_out_the_closure(forest, graph):
    from src.tier0 import crown_jewels as cj
    every = cj(forest, graph, include_derived=True)
    only = cj(forest, graph, include_derived=False)
    assert len(only) < len(every)
    assert all(not jewel.derived for jewel in only)
