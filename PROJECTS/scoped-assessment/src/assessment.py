"""The checks, each producing a finding with the evidence that justifies it.

A check here does three things and no more: it asks the target a question, it keeps
the answer, and it decides whether the answer is a finding. It does not guess, and
it does not describe what it did not see. Every finding carries the bytes the target
returned, so the report can show its work.

Two words are kept apart throughout, because conflating them is how a scanner
becomes untrustworthy. A check *observes* something. A finding is *confirmed* only
when a second, independent observation distinguishes the flaw from a coincidence --
the traversal returning a marker that could only have come from outside the root,
the redirect actually landing on another host, the listing yielding links that are
really there. A finding that cannot be confirmed says so, and the report shows which
is which rather than presenting both with the same confidence.

Exploitation stops at demonstration. The path traversal reads the one file the lab
placed outside its document root and nothing else; there is no shell, no payload, no
attempt to go further. The framework is for assessing a system you own, and the part
that matters is the evidence and the write-up.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .scan import Evidence, Finding, fetch
from .scope import Scope

__all__ = ["assess_http", "CHECK_NAMES", "CONFIRMABLE", "CHECKS", "Check"]


@dataclass(frozen=True)
class Check:
    """One check, as a value rather than as a line in a function.

    Coverage used to be a sequence of calls inside `assess_http`, which meant
    adding a check was editing the thing that runs them and the list of names was
    maintained by hand beside it. It is a table now: the names, the confirmation
    flags and the report all derive from this, so a check cannot be registered
    without running and cannot run without being registered.

    `confirmable` records whether a second observation can turn an observation into
    a confirmation. It is False for the checks that report an absence, because
    there is no second observation of nothing and calling one confirmed would claim
    more than the method allows.
    """

    id: str
    title: str
    run: Callable
    confirmable: bool = True
    needs_headers: bool = False


# The registry. Order is the order the checks run and the order the report lists
# them in, so a reader sees the shape of the assessment rather than a random order.
CHECKS: tuple = ()


def _register(*checks) -> None:
    global CHECKS
    CHECKS = tuple(checks)


# Populated at the end of the module, once the check functions exist. Declared
# here so the names are importable before then.
CHECK_NAMES: tuple = ()
CONFIRMABLE: tuple = ()

# The header set a browser uses to constrain what a page may do. Missing ones are
# reported together, because one absence is a gap and four is a posture.
SECURITY_HEADERS = (
    ("content-security-policy", "restricts where scripts and styles may come from"),
    ("x-content-type-options", "stops a browser guessing a type and running it"),
    ("x-frame-options", "stops the page being framed by another site"),
    ("referrer-policy", "limits what is leaked to sites linked to"),
)

_ABSOLUTE_PATH = re.compile(r"(?:[A-Za-z]:\\[^\s\"\'<>]+|/(?:home|usr|var|opt|srv|etc)/[^\s\"\'<>]+)")
_GIT_REF = re.compile(r"^ref:\s+refs/", re.MULTILINE)
_ENV_LINE = re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=", re.MULTILINE)
_LINK_IN_BODY = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


def _now():
    return datetime.now(timezone.utc)


def _finding(**kwargs) -> Finding:
    return Finding(**kwargs)


def assess_http(scope: Scope, host: str, port: int, scheme: str = "http",
                at: datetime | None = None, endpoints=None) -> list[Finding]:
    """Run every HTTP check against one endpoint, returning what was found.

    A check whose request the engagement refuses produces no finding and says so in
    the audit log, which is the point of routing the request through the scope
    rather than around it.
    """
    at = at or _now()
    findings: list[Finding] = []

    landing = fetch(scope, host, port, "/", scheme=scheme, at=at)
    if landing.get("refused"):
        return findings
    headers = landing.get("headers") or {}

    for check in CHECKS:
        findings.extend(check.run(scope, host, port, scheme, at))
    return findings


# --- the checks ------------------------------------------------------------

def _version_disclosure(scope, host, port, scheme, at):
    headers = (fetch(scope, host, port, "/", scheme=scheme, at=at).get("headers") or {})
    return _version_disclosure_from(host, port, headers)


def _version_disclosure_from(host, port, headers):
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if not (server or powered):
        return []
    evidence = Evidence()
    evidence.add("header", "Server", server)
    if powered:
        evidence.add("header", "X-Powered-By", powered)
    versioned = len(server.split()) > 1 or "/" in server or bool(powered)
    return [_finding(
        id="version-disclosure",
        title="The service names its own version",
        severity="Low" if versioned else "Info",
        host=host, port=port,
        detail=("The endpoint returns a product and version in its headers. That is not a "
                "vulnerability on its own; it is what lets anyone choose which "
                "vulnerabilities to try, without sending a single probing request."),
        evidence=evidence.as_list(),
        remediation=("Suppress or generalise the Server and X-Powered-By headers. The "
                     "version belongs in an inventory, not in a response."),
        business_impact=("An attacker can map the estate to known-vulnerable versions "
                         "before touching anything, which shortens the time between "
                         "choosing a target and succeeding against it."),
        confirmed=False,
        confirmation=("Not confirmable: this is a statement the target makes about itself, "
                      "and there is no second observation that would make it more true."),
    )]


def _security_headers(scope, host, port, scheme, at):
    headers = (fetch(scope, host, port, "/", scheme=scheme, at=at).get("headers") or {})
    return _security_headers_from(host, port, headers)


def _security_headers_from(host, port, headers):
    missing = [(name, why) for name, why in SECURITY_HEADERS if name not in headers]
    if not missing:
        return []
    evidence = Evidence()
    evidence.add("observation", "%d of %d expected security headers are absent"
                 % (len(missing), len(SECURITY_HEADERS)), "")
    for name, why in missing:
        evidence.add("absent", name, why)
    return [_finding(
        id="missing-security-headers",
        title="Responses do not carry the headers that constrain a browser",
        severity="Medium" if len(missing) >= 3 else "Low",
        host=host, port=port,
        detail=("The response omits %s. Each of these tells a browser to refuse to do "
                "something it would otherwise do by default, so their absence is not a "
                "bug in the application but a missing set of restraints around it. The "
                "effect is cumulative: with no policy, no type checking and no framing "
                "rule, a single injection anywhere in the site has a much shorter path to "
                "becoming an exploit." % ", ".join(name for name, _ in missing)),
        evidence=evidence.as_list(),
        remediation=("Add the headers at the edge so every response carries them, starting "
                     "with Content-Security-Policy. Begin in report-only mode and tighten "
                     "it against real traffic rather than switching it on and breaking the "
                     "site."),
        business_impact=("Without a content policy, a single reflected or stored value "
                         "becomes an executable script; without a framing rule, the site "
                         "can be overlaid by another and used to harvest clicks."),
        confirmed=False,
        confirmation=("Not confirmable: the finding is an absence, and there is no second "
                      "observation of nothing. The headers were checked individually."),
    )]


def _cookie_flags(scope, host, port, scheme, at):
    response = fetch(scope, host, port, "/login", scheme=scheme, at=at)
    raw = (response.get("headers") or {}).get("set-cookie")
    if not raw:
        return []
    lowered = raw.lower()
    flags = {"Secure": "secure" in lowered, "HttpOnly": "httponly" in lowered,
             "SameSite": "samesite" in lowered}
    missing = [name for name, present in flags.items() if not present]
    if not missing:
        return []
    name = raw.split("=", 1)[0].strip()
    evidence = Evidence()
    evidence.add("header", "Set-Cookie", raw)
    evidence.add("observation", "absent from the cookie: %s" % ", ".join(missing), "")
    return [_finding(
        id="insecure-cookie",
        title="A session cookie is set without its protective attributes",
        severity="Medium" if "Secure" in missing or "HttpOnly" in missing else "Low",
        host=host, port=port,
        detail=("The %s cookie is set without %s. Secure keeps it off a plaintext "
                "connection, HttpOnly keeps it away from scripts on the page, and "
                "SameSite stops it travelling with a request another site caused. "
                "Each one closes a specific route to stealing the session." % (
                    name, ", ".join(missing))),
        evidence=evidence.as_list(),
        remediation=("Set Secure, HttpOnly and SameSite=Lax on every session cookie. "
                     "HttpOnly cannot be added after the fact: it has to be set when the "
                     "cookie is issued."),
        business_impact=("A session token that leaks over plaintext or to a script is a "
                         "logged-in user, without the attacker needing any credential."),
        confirmed=True,
        confirmation=("The cookie was read directly from the response, and each attribute "
                      "was checked for by name in the header as sent."),
    )]


def _directory_listing(scope, host, port, scheme, at):
    for path in ("/uploads/", "/static/", "/files/"):
        response = fetch(scope, host, port, path, scheme=scheme, at=at)
        if response.get("refused") or response.get("status") != 200:
            continue
        body = response.get("body") or ""
        entries = [href for href in _LINK_IN_BODY.findall(body)
                   if href.rstrip("/") not in ("/", "") and not href.startswith("http")]
        if not entries:
            continue
        # Confirmation: a listing yields names that are really there. Ask for one
        # and see whether the server serves it.
        listed = entries[0].split("/")[-1]
        fetched = fetch(scope, host, port, path.rstrip("/") + "/" + listed, scheme=scheme, at=at)
        confirmed = fetched.get("status") == 200
        evidence = Evidence()
        evidence.add("request", "GET %s" % path, "")
        evidence.add("response", "the folder listed %d entries" % len(entries),
                     ", ".join(entries[:12]))
        evidence.add("confirmation", "the server also served %s directly" % listed,
                     "yes" if confirmed else "the listing named it but the server did not serve it")
        return [_finding(
            id="directory-listing",
            title="A folder lists its contents to anyone who asks",
            severity="Medium",
            host=host, port=port,
            detail=("The folder %s returns an index of its contents rather than refusing or "
                    "returning a page. A listing turns guessing at file names into reading "
                    "them, and it usually exposes files that were placed there rather than "
                    "published." % path),
            evidence=evidence.as_list(),
            remediation=("Turn directory indexing off, and keep files that are not meant to "
                         "be public outside the served tree rather than relying on nobody "
                         "guessing their names."),
            business_impact=("Content that was never linked to becomes discoverable, which "
                             "is how backups, exports and draft documents end up public."),
            confirmed=confirmed,
            confirmation=("A name from the listing was requested directly and the server "
                          "returned it, which a fabricated index could not do."
                          if confirmed else
                          "The listing named an entry the server then would not serve, so "
                          "the index and the content disagree."),
        )]
    return []


def _vcs_exposed(scope, host, port, scheme, at):
    for path, pattern, what in (
            ("/.git/HEAD", _GIT_REF, "a version-control reference"),
            ("/.svn/entries", None, "a Subversion working copy")):
        response = fetch(scope, host, port, path, scheme=scheme, at=at)
        if response.get("refused") or response.get("status") != 200:
            continue
        body = response.get("body") or ""
        confirmed = bool(pattern.search(body)) if pattern else bool(body.strip())
        if not body.strip():
            continue
        evidence = Evidence()
        evidence.add("request", "GET %s" % path, "")
        evidence.add("response", "the file was served", body[:300])
        return [_finding(
            id="vcs-exposed",
            title="The version-control directory is served as ordinary files",
            severity="High",
            host=host, port=port,
            detail=("The repository metadata at %s is reachable, and it identifies itself as "
                    "%s. When a repository directory is served, the objects inside it can be "
                    "downloaded one at a time and the source reconstructed -- including any "
                    "commit that was made and then reverted, because removing a file from "
                    "the working tree does not remove it from the history." % (path, what)),
            evidence=evidence.as_list(),
            remediation=("Serve the deployed tree only, never the repository that produced "
                         "it, and keep the repository outside the document root. Rotate any "
                         "credential that was ever committed, since deleting the file does "
                         "not remove it from the history."),
            business_impact=("Source code is the map to everything else: endpoints that were "
                             "never linked, keys that were committed by mistake, and the "
                             "reasoning behind each defence."),
            confirmed=confirmed,
            confirmation=("The response matched the format of %s, so the file is the real "
                          "thing rather than a page that happened to be served under that "
                          "path." % what if confirmed else
                          "The file was served but its contents did not match the expected "
                          "format, so this is reported as exposure without the stronger "
                          "claim."),
        )]
    return []


def _dotfile_exposed(scope, host, port, scheme, at):
    for path in ("/.env", "/.gitignore", "/.htaccess"):
        response = fetch(scope, host, port, path, scheme=scheme, at=at)
        if response.get("refused") or response.get("status") != 200:
            continue
        body = response.get("body") or ""
        if not body.strip():
            continue
        looks_like_config = bool(_ENV_LINE.search(body))
        evidence = Evidence()
        evidence.add("request", "GET %s" % path, "")
        evidence.add("response", "the file was served", body[:300])
        return [_finding(
            id="dotfile-exposed",
            title="A dotfile is served as an ordinary file",
            severity="Medium" if looks_like_config else "Low",
            host=host, port=port,
            detail=("The file %s is readable over HTTP. Dotfiles carry the settings a "
                    "deployment is built from, and a web server that serves them is usually "
                    "serving whatever else sits beside them." % path),
            evidence=evidence.as_list(),
            remediation=("Refuse requests whose path contains a dot-segment at the edge, and "
                         "keep configuration outside the served tree. Rotate anything the "
                         "file contained, because reading it is not the only thing that "
                         "could have happened."),
            business_impact=("Configuration holds the credentials the application uses, so "
                             "reading it is usually a step towards the database rather than "
                             "the end of the attack."),
            confirmed=looks_like_config,
            confirmation=("The contents are in the KEY=value form a configuration file "
                          "uses, so this is a real configuration file and not a page that "
                          "happened to match the path." if looks_like_config else
                          "The file was served but does not read as configuration, so it "
                          "is reported as exposure only."),
        )]
    return []


def _dangerous_method(scope, host, port, scheme, at):
    """TRACE echoes the request back, which is why it is worth knowing about."""
    from .scan import _request_with_method
    result = _request_with_method(scope, host, port, "/", "TRACE", scheme=scheme, at=at)
    if not result or result.get("refused"):
        return []
    if result.get("status") != 200:
        return []
    body = result.get("body") or ""
    confirmed = "TRACE" in body.upper()
    evidence = Evidence()
    evidence.add("request", "TRACE /", "")
    evidence.add("response", "the server answered the method", body[:300] or
                 "HTTP %s with no body" % result.get("status"))
    return [_finding(
        id="dangerous-method",
        title="The server answers an HTTP method it has no reason to",
        severity="Low",
        host=host, port=port,
        detail=("The server answered TRACE with %s. TRACE exists to echo a request back to "
                "the sender for diagnostics; left enabled, it lets a page make the browser "
                "send a request and read the response, which is how an attacker reaches "
                "headers the browser would not otherwise expose." % result.get("status")),
        evidence=evidence.as_list(),
        remediation=("Allow only the methods the application uses, and answer the rest with "
                     "405. Most deployments need GET, HEAD and POST and nothing else."),
        business_impact=("An echoed request carries whatever the browser attached to it, "
                         "including cookies and internal headers that would not otherwise be "
                         "readable from a page."),
        confirmed=confirmed,
        confirmation=("The response echoed the request line back, which is TRACE behaving "
                      "as TRACE does rather than a generic answer to an unknown method."
                      if confirmed else
                      "The method was answered with a 200 but the body did not echo the "
                      "request, so this may be a catch-all handler."),
    )]


def _open_redirect(scope, host, port, scheme, at):
    destination = "https://example.invalid/landing"
    for path in ("/redirect?to=%s" % destination, "/?next=%s" % destination):
        response = fetch(scope, host, port, path, scheme=scheme, at=at,
                         follow_redirects=False)
        if response.get("refused"):
            continue
        location = (response.get("headers") or {}).get("location")
        if not location:
            continue
        # Confirmation: does the destination leave this host? That is the whole
        # difference between a redirect and an open redirect.
        off_host = not location.startswith("/") and "example.invalid" in location
        evidence = Evidence()
        evidence.add("request", "GET %s" % path, "")
        evidence.add("response", "the response redirected to %s" % location,
                     "HTTP %s" % response.get("status"))
        return [_finding(
            id="open-redirect",
            title="A redirect goes wherever it is told, including off this host",
            severity="Medium" if off_host else "Low",
            host=host, port=port,
            detail=("The parameter is used as the redirect destination without being checked "
                    "against the site's own host. %s" % (
                        "The destination left the host entirely, which is what makes this an "
                        "open redirect rather than a convenience link."
                        if off_host else
                        "The destination was a relative path here, so the redirect is not "
                        "open as tested, but nothing in the response suggests the value is "
                        "checked at all.")),
            evidence=evidence.as_list(),
            remediation=("Redirect only to destinations on an allow-list of paths and hosts, "
                         "and prefer relative paths. Never reflect a caller-supplied URL "
                         "into a Location header."),
            business_impact=("A link that appears to be this site's own address can deliver "
                             "a user to a copy of it, which is how credentials are harvested "
                             "from people who check the domain before clicking."),
            confirmed=off_host,
            confirmation=("The Location header named a host that is not this one, which a "
                          "closed redirect could not do." if off_host else
                          "The destination was relative, so this is reported as an "
                          "unvalidated parameter rather than an open redirect."),
        )]
    return []


def _error_disclosure(scope, host, port, scheme, at):
    response = fetch(scope, host, port, "/boom", scheme=scheme, at=at)
    if response.get("refused") or response.get("status") != 500:
        return []
    body = response.get("body") or ""
    path = _ABSOLUTE_PATH.search(body)
    if not path:
        return []
    evidence = Evidence()
    evidence.add("request", "GET /boom", "")
    evidence.add("response", "the error page named a path on the server", body[:400])
    return [_finding(
        id="error-disclosure",
        title="An error page discloses the path it failed at",
        severity="Low",
        host=host, port=port,
        detail=("A failed request returned a message naming %s. A path on the server's disk "
                "tells an attacker how the deployment is laid out, which account it runs "
                "as and where to aim the next request. A stack trace is the same gift with "
                "more detail." % path.group(0)),
        evidence=evidence.as_list(),
        remediation=("Return a generic error page and log the detail where only operators "
                     "can read it. The correlation between a response and a log entry is "
                     "enough; the response itself needs to carry nothing."),
        business_impact=("Disclosed paths and stack traces shorten the reconnaissance an "
                         "attacker needs, and often reveal the framework version that a "
                         "suppressed header was hiding."),
        confirmed=True,
        confirmation=("The response contained a path in the server's own filesystem, which "
                      "the target could only produce by disclosing its layout."),
    )]


def _reflected_input(scope, host, port, scheme, at):
    probe = "zq<\">'zq"
    response = fetch(scope, host, port, "/search?q=" + probe, scheme=scheme, at=at)
    body = response.get("body") or ""
    if probe not in body:
        return []
    # Confirmation: escaping would have changed the bytes. A page that encodes its
    # output returns the probe as entities; this one returned it as typed. The
    # context is checked too, because a value between two tags is reflected while
    # the same value inside a script block is executable.
    context = body[max(0, body.find(probe) - 80):body.find(probe) + len(probe) + 80]
    in_script = "<script" in context.lower()
    evidence = Evidence()
    evidence.add("request", "GET /search?q=%s" % probe, "")
    evidence.add("response", "the probe came back with its markup intact", context)
    evidence.add("confirmation", "the angle brackets and quotes were not encoded",
                 "an encoder would have returned &lt; and &quot;")
    return [_finding(
        id="reflected-input",
        title="A parameter is reflected into the page without escaping",
        severity="High" if in_script else "Medium",
        host=host, port=port,
        detail=("A value supplied in the query string is written into the response verbatim, "
                "including its angle brackets and quotes. Reflected input is the raw "
                "material of cross-site scripting; %s" % (
                    "here it lands inside a script block, where it would run directly."
                    if in_script else
                    "here it lands in the document body, so whether it becomes script "
                    "depends on how the surrounding markup is built. This check does not "
                    "decide that, and says so rather than overstating it.")),
        evidence=evidence.as_list(),
        remediation=("Encode output for the context it is written into, and prefer templating "
                     "that escapes by default. Do not filter the input as a substitute for "
                     "encoding the output."),
        business_impact=("A crafted link can run script in a victim's session in the context "
                         "of this site, which is how session tokens and actions are taken "
                         "over."),
        confirmed=True,
        confirmation=("The probe returned byte for byte, and an encoder would necessarily "
                      "have altered the angle brackets and quotes."),
    )]


def _path_traversal(scope, host, port, scheme, at):
    """Does a file name escape the document root it is joined to?

    Confirmed by differential rather than by recognising the file: the same name is
    requested through the parameter and directly, and the finding is confirmed when
    the parameter reaches something the direct request cannot. That works on any
    target, whereas looking for a particular file's contents only works on the one
    the lab happened to place -- which is what this check used to do, and a
    confirmation that only holds for the test fixture is not a confirmation.
    """
    # The name is the same for both requests, so the only difference between them
    # is the route. A payload list of one shape would be a guess about the target;
    # these are the encodings that matter, and each is tried the same way.
    for name in ("../secret.txt", "..%2Fsecret.txt", "....//secret.txt",
                 "..%252Fsecret.txt", "../etc/passwd"):
        through = fetch(scope, host, port, "/files?name=" + name, scheme=scheme, at=at)
        if through.get("refused") or through.get("status") != 200:
            continue
        body = through.get("body") or ""
        if not body.strip():
            continue

        # The control: ask for the file by its own path. If the traversal reached
        # something, this must not reach it -- otherwise the file was public all
        # along and nothing escaped.
        direct_name = name.split("/")[-1].replace("%2F", "/").replace("%252F", "/")
        direct = fetch(scope, host, port, "/" + direct_name, scheme=scheme, at=at)
        reached_directly = direct.get("status") == 200

        # A second, independent sign for the well-known case: the contents are a
        # file of the shape they claim to be, not an error page that answered 200.
        looks_like_passwd = "root:" in body and ":/" in body
        looks_like_a_file = not body.lstrip()[:1].lower().startswith("<")

        confirmed = (not reached_directly) and looks_like_a_file
        evidence = Evidence()
        evidence.add("request", "GET /files?name=%s" % name, "")
        evidence.add("response", "the parameter returned %d bytes" % len(body), body[:400])
        evidence.add("control", "GET /%s, the file by its own path" % direct_name,
                     "HTTP %s" % direct.get("status") if not direct.get("error")
                     else direct.get("error"))
        evidence.add(
            "confirmation",
            "the same file was unreachable by its own path and reachable through the "
            "parameter, so the read escaped the root" if confirmed else
            "the file was reachable directly as well, so nothing escaped the root",
            "yes" if confirmed else "no")
        if looks_like_passwd:
            evidence.add("observation", "the contents have the shape of a password file", "")

        return [_finding(
            id="path-traversal",
            title="The file endpoint can be walked out of its document root",
            severity="High",
            host=host, port=port,
            detail=("A file name supplied in the query string is joined to the document "
                    "root and read, with nothing confining the result to that root. A "
                    "sequence of parent references therefore reads files the service was "
                    "never meant to serve. The check stopped at the first name that "
                    "worked and read nothing further."),
            evidence=evidence.as_list(),
            remediation=("Resolve the requested path and verify the result is inside the "
                         "root before opening it, and serve files by identifier rather "
                         "than by name where the content is not public."),
            business_impact=("Any file the service account can read becomes readable "
                             "remotely, which typically means configuration, keys and "
                             "credentials rather than only content."),
            confirmed=confirmed,
            confirmation=("The same name was requested directly and refused, and through "
                          "the parameter and served. Nothing in the check knows what the "
                          "file is; the difference between the two requests is the whole "
                          "evidence." if confirmed else
                          "The file was reachable by its own path as well, so this is a "
                          "file name that escaped nothing and is reported as observed "
                          "rather than confirmed."),
        )]
    return []


# The registry, filled once every check above exists. The names, the confirmation
# flags and the tests all read from here, so the three cannot drift apart. This
# block lives at the end of the module because every function it names has to
# exist before it runs -- and because a slice that rewrote the last function once
# deleted it, which is why a test now asserts the registry is not empty.
_register(
    Check("version-disclosure", "Does the service name its own version?",
          _version_disclosure, confirmable=False),
    Check("missing-security-headers", "Does the response carry the headers that "
          "constrain a browser?", _security_headers, confirmable=False),
    Check("insecure-cookie", "Is a session cookie set without its protective "
          "attributes?", _cookie_flags),
    Check("directory-listing", "Does a folder list its contents?", _directory_listing),
    Check("vcs-exposed", "Is the version-control directory served as files?",
          _vcs_exposed),
    Check("dotfile-exposed", "Is a dotfile served as an ordinary file?",
          _dotfile_exposed),
    Check("dangerous-method", "Does the server answer a method it has no reason to?",
          _dangerous_method),
    Check("open-redirect", "Does a redirect go wherever it is told?", _open_redirect),
    Check("error-disclosure", "Does an error page disclose the path it failed at?",
          _error_disclosure),
    Check("reflected-input", "Is a parameter reflected without being escaped?",
          _reflected_input),
    Check("path-traversal", "Does the file endpoint stay inside its root?",
          _path_traversal),
)

CHECK_NAMES = tuple(check.id for check in CHECKS)
CONFIRMABLE = tuple(check.id for check in CHECKS if check.confirmable)
