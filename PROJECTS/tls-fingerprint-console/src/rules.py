"""Alert rules for the TLS Fingerprint Console.

Every rule is a standalone ``rule(event, ctx) -> list[alert]`` callable, so it
can be unit-tested in isolation.  An alert is a plain dict::

    {"rule": str, "severity": str, "title": str, "detail": str}

``evaluate`` runs every rule over one event and *never* raises: a malformed
event (wrong types, missing keys) simply means the affected rules do not fire.

ctx is a plain dict.  Recognised keys:

    seen_before : callable(kind, value) -> bool   (first_seen)
    history     : list[event]                      (fp_rotation, monoculture)
    os_by_ja3   : dict[ja3 -> os family]           (os_mismatch)
    window      : int, seconds (default 300)       (fp_rotation, monoculture)
    corpus      : object with .match(kind, value)  (known_bad detail)
    fp_family   : dict[kind -> {value: family}]    (ua_mismatch override)
    store       : object with .events()            (history fallback)

Every key is optional; a missing key means the rule that needs it stays quiet.
"""

from __future__ import annotations

FP_KINDS = ("ja3", "ja4", "ja3s", "ja4s", "ja4x", "ja4t", "ja4h")

# --------------------------------------------------------------------------
# Client-family vocabulary used by ua_mismatch.  Chrome, Firefox, Safari and
# Edge all collapse to "browser": the rule only cares which *family* the
# fingerprint belongs to, not which build.
# --------------------------------------------------------------------------
_BROWSER_FAMILIES = {"browser", "chrome", "chromium", "firefox", "safari",
                     "edge", "ie", "opera"}

# An extensible allow-list of well-known JA3 / JA4 values -> client family.
# These hashes are version- and build-dependent and site-specific; extend this
# from your own telemetry or corpus.  Anything absent here is treated as
# "unknown", and an unknown fingerprint NEVER triggers ua_mismatch.
KNOWN_FP_FAMILY = {
    "ja3": {
        # Chrome / Chromium desktop
        "b32309a26951912be7dba376398abc3b": "browser",
        "3b5074b1b5d032e5620f69f9f700ff0e": "browser",
        # Firefox desktop
        "cd08e31494f9531f560d64c695473da9": "browser",
        # curl / OpenSSL
        "51c64c77e60f3980eea90869b68c58a8": "curl",
        # Go net/http
        "aa56c057ad164ec4fdcb7a5a283be9fc": "go",
    },
    "ja4": {
        # Chrome
        "t13d1516h2_8daaf6152771_02713d6af862": "browser",
        # Firefox
        "t13d1715h2_5b57614c22b0_3d5424432f57": "browser",
        # curl
        "t13d1516h1_8daaf6152771_e5627efa2ab1": "curl",
        # Go net/http
        "t13d1517h2_8daaf6152771_8b2b2b1e0d0a": "go",
    },
}

# intel categories that count as "known bad"
BAD_CATEGORIES = {"malware", "c2"}

MONOCULTURE_MIN_IPS = 10
FP_ROTATION_MIN_JA4 = 3
DEFAULT_WINDOW = 300


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def _alert(rule, severity, title, detail):
    return {"rule": rule, "severity": severity, "title": title, "detail": detail}


def _ctx(ctx):
    return ctx if isinstance(ctx, dict) else {}


def _fps(event):
    if not isinstance(event, dict):
        return {}
    f = event.get("fingerprints")
    return f if isinstance(f, dict) else {}


def _fp(event, kind):
    v = _fps(event).get(kind)
    return v if isinstance(v, str) and v else None


def _primary_fp(event):
    """The fingerprint we treat as the host's identity: JA4, else JA3."""
    for kind in ("ja4", "ja3", "ja4s", "ja3s"):
        v = _fp(event, kind)
        if v:
            return kind, v
    return None, None


def _window(ctx):
    w = _ctx(ctx).get("window")
    return w if isinstance(w, (int, float)) and w > 0 else DEFAULT_WINDOW


def _history(ctx):
    """Prior events from ctx['history'], falling back to ctx['store'].events()."""
    hist = _ctx(ctx).get("history")
    if hist is None:
        store = _ctx(ctx).get("store")
        if store is not None and hasattr(store, "events"):
            try:
                hist = store.events()
            except Exception:
                hist = None
    return hist if isinstance(hist, list) else []


def _recent(event, ctx):
    """History events at or before *event* and within ctx['window'] seconds."""
    ts = event.get("ts") if isinstance(event, dict) else None
    if not isinstance(ts, (int, float)):
        return []
    w = _window(ctx)
    out = []
    for e in _history(ctx):
        if not isinstance(e, dict):
            continue
        et = e.get("ts")
        if isinstance(et, (int, float)) and et <= ts and (ts - et) <= w:
            out.append(e)
    return out


# --------------------------------------------------------------------------
# known_bad
# --------------------------------------------------------------------------
def _matched_fp(event, ctx, category):
    """Return (kind, value, intel_name) for the fingerprint the corpus matched.

    Uses ctx['corpus'].match when available; otherwise falls back to the first
    fingerprint carried on the event, in a stable priority order.
    """
    fps = _fps(event)
    corpus = _ctx(ctx).get("corpus")
    if corpus is not None and hasattr(corpus, "match"):
        for kind in FP_KINDS:
            value = fps.get(kind)
            if not isinstance(value, str) or not value:
                continue
            try:
                entry = corpus.match(kind, value)
            except Exception:
                entry = None
            if entry is None:
                continue
            if isinstance(entry, dict):
                cat = entry.get("category")
                name = entry.get("name")
            else:
                cat = getattr(entry, "category", None)
                name = getattr(entry, "name", None)
            if isinstance(cat, str) and cat.lower() in BAD_CATEGORIES:
                return kind, value, name
    for kind in FP_KINDS:
        value = fps.get(kind)
        if isinstance(value, str) and value:
            return kind, value, event.get("intel_name")
    return None, None, event.get("intel_name")


def _intel_verdict(event, ctx):
    """Return (kind, value, category, name) for the fingerprint intel matched.

    The event's own ``category`` and ``intel_name`` win when the caller has
    already enriched it.  Otherwise the corpus is consulted directly, because
    the API hands the rules raw events -- a rule that only ever fired on
    pre-labelled input is dead code, which is what this rule was until the
    lookup below was added.
    """
    fps = _fps(event)
    corpus = _ctx(ctx).get("corpus")
    if corpus is not None and hasattr(corpus, "match"):
        for kind in FP_KINDS:
            value = fps.get(kind)
            if not isinstance(value, str) or not value:
                continue
            try:
                entry = corpus.match(kind, value)
            except Exception:
                entry = None
            if entry is None:
                continue
            if isinstance(entry, dict):
                cat = entry.get("category")
                name = entry.get("name")
            else:
                cat = getattr(entry, "category", None)
                name = getattr(entry, "name", None)
            cat = cat.lower() if isinstance(cat, str) else None
            if cat:
                return kind, value, cat, (event.get("intel_name") or name)

    declared = event.get("category")
    declared = declared.lower() if isinstance(declared, str) else None
    if declared:
        for kind in FP_KINDS:
            value = fps.get(kind)
            if isinstance(value, str) and value:
                return kind, value, declared, event.get("intel_name")
    return None, None, None, event.get("intel_name")


def known_bad(event, ctx):
    """critical: a fingerprint on the event matches a malware / c2 intel entry."""
    if not isinstance(event, dict):
        return []
    kind, value, category, name = _intel_verdict(event, _ctx(ctx))
    if category not in BAD_CATEGORIES:
        return []
    detail = (
        "intel verdict {cat!r}: fingerprint {kind}={value} matched intel name "
        "{name!r}".format(cat=category, kind=kind, value=value, name=name or "unknown")
    )
    return [_alert("known_bad", "critical", "known-bad fingerprint", detail)]


# --------------------------------------------------------------------------
# ua_mismatch
# --------------------------------------------------------------------------
def _norm_family(fam):
    if not isinstance(fam, str):
        return None
    f = fam.strip().lower()
    if f in _BROWSER_FAMILIES:
        return "browser"
    return f or None


def _ua_family(ua):
    """Map a User-Agent string to a client family, or None if unrecognised."""
    if not isinstance(ua, str) or not ua:
        return None
    s = ua.lower()
    if "curl/" in s or s.startswith("curl"):
        return "curl"
    if "python-requests" in s or "python-urllib" in s or "aiohttp" in s or "httpx" in s:
        return "python-requests"
    if "go-http-client" in s or s.startswith("go/"):
        return "go"
    if "powershell" in s:
        return "powershell"
    if "mozilla/" in s or "applewebkit" in s or "gecko/" in s or "opera/" in s:
        return "browser"
    return None


def _family_table(ctx):
    table = {k: dict(v) for k, v in KNOWN_FP_FAMILY.items()}
    extra = _ctx(ctx).get("fp_family")
    if isinstance(extra, dict):
        for kind, mapping in extra.items():
            if isinstance(mapping, dict):
                table.setdefault(kind, {}).update(mapping)
    return table


def _fp_family(event, ctx):
    table = _family_table(ctx)
    for kind in ("ja4", "ja3", "ja4s", "ja3s", "ja4x", "ja4t", "ja4h"):
        value = _fp(event, kind)
        if value:
            fam = table.get(kind, {}).get(value)
            if fam:
                return kind, value, _norm_family(fam)
    return None, None, None


def ua_mismatch(event, ctx):
    """medium: the declared User-Agent names a different family than the
    fingerprint indicates.  Silent when either side is unknown."""
    if not isinstance(event, dict):
        return []
    declared = _ua_family(event.get("user_agent"))
    if declared is None:
        return []
    kind, value, fp_fam = _fp_family(event, _ctx(ctx))
    if fp_fam is None or declared == fp_fam:
        return []
    detail = (
        "User-Agent declares {declared!r} but fingerprint {kind}={value} "
        "indicates {fp!r}".format(declared=declared, kind=kind, value=value, fp=fp_fam)
    )
    return [_alert("ua_mismatch", "medium", "the user-agent is lying", detail)]


# --------------------------------------------------------------------------
# os_mismatch
# --------------------------------------------------------------------------
_OS_ALIASES = {
    "windows": "windows", "win": "windows", "win32": "windows", "win64": "windows",
    "macos": "macos", "mac": "macos", "osx": "macos", "mac os x": "macos",
    "darwin": "macos",
    "linux": "linux", "gnu/linux": "linux", "ubuntu": "linux",
    "unix": "unix", "nix": "unix", "bsd": "unix", "freebsd": "unix",
    "android": "android",
    "ios": "ios", "iphone": "ios", "ipad": "ios", "ipados": "ios",
}


def _norm_os(value):
    if not isinstance(value, str):
        return None
    return _OS_ALIASES.get(value.strip().lower())


def _ua_os(ua):
    """Map a User-Agent string to an OS family, or None if unrecognised."""
    if not isinstance(ua, str) or not ua:
        return None
    s = ua.lower()
    if "android" in s:
        return "android"
    if "iphone" in s or "ipad" in s or "ipod" in s or "ios" in s:
        return "ios"
    if "windows" in s or "win32" in s or "win64" in s:
        return "windows"
    if "macintosh" in s or "mac os x" in s or "darwin" in s or "macos" in s:
        return "macos"
    if "linux" in s or "x11" in s or "ubuntu" in s:
        return "linux"
    return None


# A JA3 identifies a TLS stack, not an operating system.  The bundled
# salesforce list is the OSX/*nix client list, so its entries are Unix-family
# stacks: macOS and Linux share them and cannot be told apart from a
# fingerprint.  Treating the whole Unix family as compatible stops the rule
# inventing a mismatch between two systems that look identical on the wire.
_UNIX_FAMILY = {"unix", "macos", "linux", "bsd", "freebsd", "openbsd", "solaris"}


def _os_compatible(mapped, declared):
    """True when a fingerprint's OS and a declared OS are consistent."""
    if mapped == declared:
        return True
    return mapped in _UNIX_FAMILY and declared in _UNIX_FAMILY


def os_mismatch(event, ctx):
    """medium: the User-Agent's declared OS contradicts the OS mapped from the
    event's JA3.  Silent when the JA3 is unknown to ctx['os_by_ja3']."""
    if not isinstance(event, dict):
        return []
    declared = _ua_os(event.get("user_agent"))
    if declared is None:
        return []
    ja3 = _fp(event, "ja3")
    if not ja3:
        return []
    mapping = _ctx(ctx).get("os_by_ja3")
    if not isinstance(mapping, dict):
        return []
    mapped = _norm_os(mapping.get(ja3))
    if mapped is None or _os_compatible(mapped, declared):
        return []
    detail = (
        "JA3 {ja3} maps to OS {mapped!r} but User-Agent declares {declared!r}"
    ).format(ja3=ja3, mapped=mapped, declared=declared)
    return [_alert("os_mismatch", "medium", "the stack betrays the os", detail)]


# --------------------------------------------------------------------------
# first_seen
# --------------------------------------------------------------------------
def first_seen(event, ctx):
    """info: the first time a (kind, value) fingerprint pair is observed."""
    if not isinstance(event, dict):
        return []
    seen_before = _ctx(ctx).get("seen_before")
    if not callable(seen_before):
        return []
    out = []
    fps = _fps(event)
    for kind in FP_KINDS:
        value = fps.get(kind)
        if not isinstance(value, str) or not value:
            continue
        try:
            seen = bool(seen_before(kind, value))
        except Exception:
            # cannot tell -> do not guess
            continue
        if not seen:
            out.append(_alert("first_seen", "info", "first sighting",
                              "first observation of {kind}={value}".format(
                                  kind=kind, value=value)))
    return out


# --------------------------------------------------------------------------
# fp_rotation
# --------------------------------------------------------------------------
def fp_rotation(event, ctx):
    """high: one src_ip presents >=3 distinct JA4s for the same SNI in-window."""
    if not isinstance(event, dict):
        return []
    src = event.get("src_ip")
    sni = event.get("sni")
    if not src or not sni:
        return []
    rel = _recent(event, ctx)
    rel.append(event)
    ja4s = set()
    for e in rel:
        if e.get("src_ip") != src or e.get("sni") != sni:
            continue
        v = _fp(e, "ja4")
        if v:
            ja4s.add(v)
    if len(ja4s) < FP_ROTATION_MIN_JA4:
        return []
    detail = (
        "{src} presented {n} distinct JA4 fingerprints for SNI {sni!r} within "
        "{w}s".format(src=src, n=len(ja4s), sni=sni, w=_window(ctx))
    )
    return [_alert("fp_rotation", "high", "identity rotation", detail)]


# --------------------------------------------------------------------------
# monoculture
# --------------------------------------------------------------------------
def monoculture(event, ctx):
    """medium: one fingerprint value is presented by >=10 distinct src_ips."""
    if not isinstance(event, dict):
        return []
    kind, value = _primary_fp(event)
    if not value:
        return []
    rel = _recent(event, ctx)
    rel.append(event)
    ips = set()
    for e in rel:
        if _fp(e, kind) != value:
            continue
        ip = e.get("src_ip")
        if ip:
            ips.add(ip)
    if len(ips) < MONOCULTURE_MIN_IPS:
        return []
    detail = (
        "{kind}={value} presented by {n} distinct source IPs within {w}s".format(
            kind=kind, value=value, n=len(ips), w=_window(ctx))
    )
    return [_alert("monoculture", "medium", "one toolkit, many hosts", detail)]


# --------------------------------------------------------------------------
# ech_obscured
# --------------------------------------------------------------------------
def ech_obscured(event, ctx):
    """info: the ClientHello offered ECH, so the handshake is hidden.

    This is not a threat but a visibility limit: with ECH the outer hello is
    deliberately generic and the SNI is a public name, so the fingerprint only
    describes the outer shell.  Fires solely on the event's ``ech`` flag -- the
    rule never re-parses anything, and stays quiet when the flag is absent or
    false.
    """
    if not isinstance(event, dict):
        return []
    if event.get("ech") is not True:
        return []
    public_name = event.get("sni")
    if not isinstance(public_name, str) or not public_name:
        public_name = "unknown"
    detail = (
        "the ClientHello offered Encrypted Client Hello (ECH): the SNI "
        "{sni!r} is a public name, not the real destination, and the "
        "fingerprint describes the outer hello only".format(sni=public_name)
    )
    return [_alert("ech_obscured", "info", "the handshake is hidden", detail)]


# --------------------------------------------------------------------------
# evaluate
# --------------------------------------------------------------------------
RULES = (known_bad, ua_mismatch, os_mismatch, first_seen, fp_rotation, monoculture,
         ech_obscured)


def evaluate(event, ctx=None):
    """Run every rule; return the concatenated alerts.  Never raises."""
    ctx = _ctx(ctx)
    out = []
    if not isinstance(event, dict):
        return out
    for rule in RULES:
        try:
            alerts = rule(event, ctx)
        except Exception:
            alerts = []
        if alerts:
            out.extend(alerts)
    return out
