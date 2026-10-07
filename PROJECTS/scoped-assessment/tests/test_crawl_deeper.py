"""What the crawl can see beyond a plain <a href>.

A link written in HTML is easy; a path assembled in a script is not, and a site
that declares paths in robots.txt rather than linking them is common. Both are
covered, and the limit of the method is asserted rather than described, so that a
future change that quietly stops seeing them fails here.
"""

from __future__ import annotations

import json

import pytest

from lab import LabServer
from src.crawl import _declared_paths, _script_links, crawl
from src.scope import load_scope


@pytest.fixture(scope="module")
def lab():
    with LabServer(port=0) as server:
        yield server


def engagement(tmp_path, ports):
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps({
        "engagement": "test", "targets": [{"host": "127.0.0.1", "ports": list(ports)}],
        "allowed_actions": ["connect"]}), encoding="utf-8")
    return load_scope(path, audit_path=tmp_path / "audit.jsonl")


def test_a_path_built_inside_a_script_is_found(tmp_path, lab):
    """The lab reaches /api/reports only from a string inside a <script>, so a
    crawler reading only <a href> would miss it entirely."""
    scope = engagement(tmp_path, [lab.port])
    result = crawl(scope, "127.0.0.1", lab.port)
    paths = {endpoint["path"] for endpoint in result["endpoints"]}
    assert "/api/reports" in paths, sorted(paths)


def test_a_script_src_is_followed():
    body = '<html><script src="/assets/app.js"></script></html>'
    assert list(_script_links("http://h:1/", body)) == ["http://h:1/assets/app.js"]


def test_a_quoted_path_in_a_script_is_found():
    body = """<script>fetch("/api/thing"); var x = '/other/place';</script>"""
    found = list(_script_links("http://h:1/", body))
    assert "http://h:1/api/thing" in found
    assert "http://h:1/other/place" in found


def test_a_script_that_builds_a_path_from_fragments_is_only_partly_seen():
    """The honest limit, stated as a test rather than a claim.

    This is a regular expression, not a parser. Given a path assembled from
    fragments it finds the literal prefix and not the path, so it visits `/api/`
    and never `/api/reports`. That is the difference between a link follower and a
    browser, and the report says so rather than implying it saw everything.
    """
    body = """<script>var p = "/api/" + "re" + "ports"; fetch(p);</script>"""
    found = list(_script_links("http://h:1/", body))
    assert found == ["http://h:1/api/"]
    assert "http://h:1/api/reports" not in found


def test_a_path_declared_in_robots_is_read():
    body = "User-agent: *\nDisallow: /internal/status\nDisallow: /uploads/\n"
    assert set(_declared_paths(body)) == {"/internal/status", "/uploads/"}


def test_a_sitemap_names_paths():
    body = "<urlset><url><loc>http://h:1/one</loc></url><url><loc>http://h:1/two</loc></url></urlset>"
    assert set(_declared_paths(body)) == {"http://h:1/one", "http://h:1/two"}


def test_a_declared_path_is_visited_even_though_nothing_links_to_it(tmp_path, lab):
    """robots.txt is a site saying what it has, and a crawler that ignores it is
    ignoring the site's own index of itself."""
    scope = engagement(tmp_path, [lab.port])
    result = crawl(scope, "127.0.0.1", lab.port)
    paths = {endpoint["path"] for endpoint in result["endpoints"]}
    assert "/internal/status" in paths, sorted(paths)


def test_robots_txt_itself_is_read(tmp_path, lab):
    scope = engagement(tmp_path, [lab.port])
    result = crawl(scope, "127.0.0.1", lab.port)
    assert any("robots.txt" in endpoint["url"] for endpoint in result["endpoints"])
