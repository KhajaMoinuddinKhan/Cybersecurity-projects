"""Following the application rather than guessing at it.

A scanner that tests three paths tests the three paths somebody typed. What an
application actually exposes is what it links to, so this walks the links -- within
the engagement, at a bounded depth, and with a deliberate refusal to follow
anything that looks like it would change state.

That last part is not politeness. A crawler that follows every link it finds will
eventually follow a `?action=delete` or a `/logout`, and an assessment that
deleted a record has caused the incident it was hired to find. Links matching a
list of state-changing words are recorded and not followed, and the record of what
was skipped is part of the crawl's output.

Parsing is done with regular expressions rather than an HTML parser, for the same
reason the report has no stylesheet: this ships as standard library only. It is
less complete than a real parser and it says so -- a link built by JavaScript is
invisible to it, and the report does not claim to have found what it cannot see.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from .scan import fetch

__all__ = ["CrawlError", "Page", "Endpoint", "crawl", "STATE_CHANGING"]

# Words that suggest following the link would change something. Not exhaustive,
# and it does not need to be: it needs to catch the common ones and it needs to
# fail towards not following.
STATE_CHANGING = (
    "logout", "log-out", "signout", "sign-out", "delete", "remove", "destroy",
    "drop", "unsubscribe", "cancel", "revoke", "deactivate", "disable", "purge",
    "reset", "reboot", "restart", "shutdown", "terminate", "kill", "clear",
)

_LINK = re.compile(r"""<a\s[^>]*href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_SCRIPT_BLOCK = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
_SCRIPT_SRC = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
# A URL in a script is usually a quoted string that starts with a slash or a
# scheme. Not a JavaScript parser -- a parser would need a library, and the point
# is to see the obvious ones rather than to be complete.
_JS_URL = re.compile(r"""["']((?:https?:)?/[^"'\s\\<>]{1,120})["']""")
# Paths a site declares rather than links: the two files a crawler is meant to read.
_DECLARED = ("/robots.txt", "/sitemap.xml")
_FORM = re.compile(r"<form\s[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_FORM_ATTR = re.compile(r"""(\w+)\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_INPUT = re.compile(r"""<(?:input|select|textarea)\s[^>]*>""", re.IGNORECASE)
_SKIP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "about:")


class CrawlError(RuntimeError):
    """The crawl could not be run as asked."""


@dataclass
class Endpoint:
    """Something the application exposed, and how it was reached."""
    url: str
    path: str
    method: str = "GET"
    parameters: tuple = ()
    form: bool = False
    source: str = ""

    def as_dict(self) -> dict:
        return {"url": self.url, "path": self.path, "method": self.method,
                "parameters": list(self.parameters), "form": self.form,
                "source": self.source}


@dataclass
class Page:
    url: str
    status: int = 0
    content_type: str = ""
    body: str = ""
    headers: dict = field(default_factory=dict)
    refused: bool = False
    reason: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.refused and not self.error and 200 <= self.status < 300


def _same_target(base: str, candidate: str) -> bool:
    """Only follow links that stay on the host and port we started from.

    A link to another host is somebody else's system. The engagement named one
    target, and a crawler that wandered off it would be assessing a host nobody
    gave permission to assess.
    """
    one, two = urlparse(base), urlparse(candidate)
    return (one.scheme, one.netloc) == (two.scheme, two.netloc)


def _is_state_changing(url: str) -> bool:
    parsed = urlparse(url)
    haystack = (parsed.path + "?" + parsed.query).lower()
    return any(word in haystack for word in STATE_CHANGING)


def _normalise(base: str, href: str) -> str | None:
    href = (href or "").strip()
    if not href or href.startswith("#") or href.lower().startswith(_SKIP_SCHEMES):
        return None
    absolute = urljoin(base, href)
    parsed = urlparse(absolute)
    if parsed.scheme not in ("http", "https"):
        return None
    # strip the fragment: it is resolved by the browser and never sent
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/",
                       parsed.params, parsed.query, ""))


def _links(base: str, body: str):
    for match in _LINK.finditer(body or ""):
        candidate = _normalise(base, match.group(1))
        if candidate:
            yield candidate


def _script_links(base: str, body: str):
    """Paths a page builds in JavaScript rather than writing as a link.

    A regular expression is not a JavaScript parser and this does not pretend to be
    one: it finds quoted strings that look like paths, which catches the common
    shape and misses anything assembled from fragments. The report says the crawl
    can only see what it can read, so the limit is stated rather than hidden.
    """
    for block in _SCRIPT_BLOCK.finditer(body or ""):
        for match in _JS_URL.finditer(block.group(1)):
            candidate = _normalise(base, match.group(1))
            if candidate:
                yield candidate
    for match in _SCRIPT_SRC.finditer(body or ""):
        candidate = _normalise(base, match.group(1))
        if candidate:
            yield candidate


def _declared_paths(body: str):
    """Paths named in robots.txt or a sitemap, which are declared rather than linked."""
    for line in (body or "").splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                yield path
        for match in re.finditer(r"<loc>\s*(.*?)\s*</loc>", line, re.IGNORECASE):
            # finditer, not find: a sitemap puts every loc on one line and reading
            # only the first would visit one page of a site's whole index.
            yield match.group(1).strip()


def _forms(base: str, body: str):
    """Every form, with its action, method and fields.

    Fields are recorded because a form is the application telling you where it
    takes input, which is exactly where the input checks belong.
    """
    for match in _FORM.finditer(body or ""):
        block = match.group(0)
        attributes = {name.lower(): value for name, value in _FORM_ATTR.findall(
            block[:block.find(">") + 1])}
        action = _normalise(base, attributes.get("action", "")) or base
        method = (attributes.get("method") or "GET").upper()
        names = []
        for tag in _INPUT.finditer(block):
            fields = {name.lower(): value for name, value in _FORM_ATTR.findall(tag.group(0))}
            name = fields.get("name")
            if name and name not in names:
                names.append(name)
        yield action, method, tuple(names)


def crawl(scope, host: str, port: int, start: str = "/", max_pages: int = 25,
          max_depth: int = 3, scheme: str = "http", throttle=None,
          at=None) -> dict:
    """Walk the application from `start`, staying inside the engagement.

    Returns the pages that were read, the endpoints that were discovered, and the
    links that were deliberately not followed. That third list is not a debug
    detail: it is the crawl's account of what it declined to touch.
    """
    if max_pages < 1:
        raise CrawlError("a crawl with no pages is not a crawl")
    if max_depth < 0:
        raise CrawlError("the depth cannot be negative")

    root = "%s://%s:%d" % (scheme, host, port)
    seen: dict = {}
    endpoints: dict = {}
    skipped: list = []
    queue = [(_normalise(root, start) or root + "/", 0)]
    # The two files a site publishes to say what it has, read before the walk so
    # that a path nobody linked to is still visited.
    for declared in _DECLARED:
        queue.append((root + declared, 0))
    read = 0

    def read_page(url):
        # fetch takes a path and builds the URL itself; handing it a whole URL
        # produced "http://host:porthttp://host:port/" and every page failed.
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return fetch(scope, host, port, path, scheme=parsed.scheme or scheme, at=at)

    while queue and read < max_pages:
        batch = []
        while queue and len(batch) < max(1, getattr(throttle, "workers", 1)):
            url, depth = queue.pop(0)
            if url in seen:
                continue
            seen[url] = depth
            batch.append((url, depth))
        if not batch:
            break

        if throttle is not None:
            responses = throttle.run([(lambda u=u: read_page(u)) for u, _ in batch])
        else:
            responses = [read_page(url) for url, _ in batch]

        for (url, depth), response in zip(batch, responses, strict=False):
            read += 1
            page = Page(url=url, status=response.get("status", 0),
                        content_type=(response.get("headers", {}) or {}).get("content-type", ""),
                        body=response.get("body", "") or "",
                        headers=response.get("headers", {}) or {},
                        refused=response.get("refused", False),
                        reason=response.get("reason", ""),
                        error=response.get("error", ""))
            if not page.ok:
                continue
            parsed = urlparse(url)
            if parsed.query:
                endpoints.setdefault(url, Endpoint(
                    url=url, path=parsed.path, method="GET",
                    parameters=tuple(sorted(parse_qs(parsed.query))),
                    source="link"))
            else:
                endpoints.setdefault(url, Endpoint(url=url, path=parsed.path, source="link"))

            # A robots.txt or sitemap names paths; those are queued rather than
            # treated as pages to link from.
            if parsed.path in _DECLARED:
                for declared in _declared_paths(page.body):
                    candidate = _normalise(root + "/", declared)
                    if candidate and _same_target(root, candidate) and candidate not in seen:
                        queue.append((candidate, 1))
                continue

            if depth >= max_depth:
                continue

            for action, method, names in _forms(url, page.body):
                endpoints.setdefault(action, Endpoint(
                    url=action, path=urlparse(action).path, method=method,
                    parameters=names, form=True, source=url))

            candidates = list(_links(url, page.body)) + list(_script_links(url, page.body))
            for candidate in candidates:
                if not _same_target(root, candidate):
                    skipped.append({"url": candidate, "reason": "a different host"})
                    continue
                if _is_state_changing(candidate):
                    skipped.append({"url": candidate, "reason": "the path suggests it changes state"})
                    continue
                if candidate not in seen:
                    queue.append((candidate, depth + 1))

    # A link refused on five pages is one decision, not five. Deduplicated so the
    # record reads as the decisions that were made rather than as a tally.
    deduped = []
    for item in skipped:
        if item not in deduped:
            deduped.append(item)
    return {
        "start": root + start,
        "pages_read": read,
        "endpoints": [endpoint.as_dict() for endpoint in endpoints.values()],
        "skipped": deduped,
        "not_followed": len(deduped),
        "limit": {"max_pages": max_pages, "max_depth": max_depth},
        "exhausted": not queue,
    }
