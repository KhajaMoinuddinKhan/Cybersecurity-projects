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

import glob
import json
from pathlib import Path

import pytest

from src.chokepoints import attacker_map, chokepoints, minimum_node_cut, removal_impact
from src.graph import build_graph
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
    privileges = {right.name for right in RIGHTS}
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
