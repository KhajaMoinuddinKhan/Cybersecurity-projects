r"""Confidence-scored fingerprint matching and per-source diversity statistics.

The corpus (see :mod:`src.corpus`) answers exactly one question -- "is this
fingerprint a known entry?" -- and real fingerprinting work is messier than
that.  A browser that upgrades from Chrome 119 to 120 changes the JA4's
a-section *and* its extension hash while keeping the same cipher list; a JA3 is
a single opaque md5 with no internal structure to compare at all.  This module
adds the two things the console needs to be useful on real traffic:

* :func:`match_fingerprint` -- identify a fingerprint even when it is not an
  exact corpus hit, and say how sure we are.
* :func:`match_event` -- run that over every fingerprint an event carries.
* :func:`diversity` -- summarise how varied each source's fingerprints are.

JA4 / JA4S structure (see :mod:`src.ja4`)::

    t13d1516h2_8daaf6152771_e5627efa2ab1
    \_________/ \_________/ \_________/
     a-section    b-section    c-section

The b-section is a truncated sha256 of the *sorted cipher list*; the c-section
is a truncated sha256 of the *sorted extension list plus the signature
algorithms*.  Both are hashes of the client's real cryptographic preferences,
not of its build number, so they survive version bumps: two JA4s that share a
b-section present the same cipher list, and two that share both b and c are
almost certainly the same TLS stack in a different build.  That is the entire
basis for the fuzzy score below -- we score what actually carries identity and
refuse to invent a number where it does not.
"""

from __future__ import annotations

from typing import Optional

# Every fingerprint kind the console understands, in the same stable order the
# rest of the codebase uses.
FP_KINDS = ("ja3", "ja3s", "ja4", "ja4s", "ja4x", "ja4t", "ja4h")

# The only kinds whose value has an interpretable cipher-hash and extension-hash
# pair.  JA4X/JA4T/JA4H hash different material (certificate OIDs, TCP options,
# HTTP headers) and JA3/JA3S are a single opaque md5, so none of those can be
# partially matched against a corpus entry.
JA4_KINDS = ("ja4", "ja4s")

# Kinds that are a single opaque md5 with no sections to compare.
OPAQUE_KINDS = ("ja3", "ja3s")

# Named scores, so the reasoning is visible at the call site and in tests.
SCORE_EXACT = 1.0        # exact (kind, value) match
SCORE_B_AND_C = 0.8      # same cipher list and extension list, a-section differs
SCORE_B_ONLY = 0.5       # same cipher list only
SCORE_C_ONLY = 0.4       # same extension list only

MAX_CANDIDATES = 5


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def _norm(s) -> str:
    return str(s).strip().lower()


def _sections(value) -> Optional[tuple]:
    """Split a JA4-family value into ``(a, b, c)`` or return ``None``.

    A JA4/JA4S value is exactly three underscore-separated fields.  Anything
    else -- empty, wrong arity, an empty field -- has no sections to compare, so
    it is reported as unparseable rather than compared field by field on a
    guess.
    """
    if not isinstance(value, str):
        return None
    parts = value.strip().lower().split("_")
    if len(parts) != 3:
        return None
    a, b, c = parts
    if not a or not b or not c:
        return None
    return a, b, c


def _entry_field(entry, name):
    """Read a field from an Entry object or a plain dict entry."""
    if isinstance(entry, dict):
        return entry.get(name)
    return getattr(entry, name, None)


def _entries(corpus) -> list:
    """Every entry in *corpus*, or ``[]`` if it has no usable ``entries()``."""
    if corpus is None:
        return []
    getter = getattr(corpus, "entries", None)
    if not callable(getter):
        return []
    try:
        return list(getter() or [])
    except Exception:
        return []


def _corpus_match(corpus, kind, value):
    """Exact lookup via ``corpus.match``; ``None`` on any failure."""
    if corpus is None:
        return None
    matcher = getattr(corpus, "match", None)
    if not callable(matcher):
        return None
    try:
        return matcher(kind, value)
    except Exception:
        return None


def _match_dict(entry) -> dict:
    return {
        "value": _entry_field(entry, "value"),
        "name": _entry_field(entry, "name"),
        "category": _entry_field(entry, "category"),
        "source": _entry_field(entry, "source"),
        "license": _entry_field(entry, "license"),
    }


def _candidate_dict(entry, score: float) -> dict:
    return {
        "value": _entry_field(entry, "value"),
        "name": _entry_field(entry, "name"),
        "category": _entry_field(entry, "category"),
        "source": _entry_field(entry, "source"),
        "score": score,
    }


def _fp_value(fps, kind) -> Optional[str]:
    value = fps.get(kind) if isinstance(fps, dict) else None
    return value if isinstance(value, str) and value else None


# --------------------------------------------------------------------------
# match_fingerprint
# --------------------------------------------------------------------------
def match_fingerprint(kind, value, corpus) -> dict:
    """Identify *value* against *corpus* with a confidence and a reason.

    Returns::

        {"value", "kind", "match", "confidence", "basis", "candidates"}

    where ``match`` is the identified entry (or ``None``), ``confidence`` is a
    float in ``[0.0, 1.0]``, ``basis`` is a short plain-English reason, and
    ``candidates`` is up to :data:`MAX_CANDIDATES` ``{value, name, category,
    source, score}`` dicts, best first.

    Scoring, applied in this order (documented so the numbers are auditable):

    1. An exact match on ``kind`` + ``value`` scores ``1.0`` ("exact match").
       The matched entry is also the single candidate, so a positive
       confidence always comes with at least one candidate.
    2. A JA4/JA4S with no exact match is compared section by section against
       every same-kind corpus entry::

           b and c both match  -> 0.8  (same stack, different build/SNI/ALPN)
           b matches only      -> 0.5  (same cipher list)
           c matches only      -> 0.4  (same extension list)

    3. A JA3 (or JA3S) has no sections, so a near miss is not evidence of
       anything and returns ``0.0`` with no candidates -- the basis says so
       instead of inventing a score.

    Never raises: a missing corpus, an unparseable value or a malformed entry
    all degrade to "no confident match".
    """
    kind_n = _norm(kind)
    raw = value if isinstance(value, str) else ("" if value is None else str(value))

    result = {
        "value": raw,
        "kind": kind_n,
        "match": None,
        "confidence": 0.0,
        "basis": "",
        "candidates": [],
    }

    # 1. exact match wins outright.
    exact = _corpus_match(corpus, kind_n, raw)
    if exact is not None:
        result["match"] = _match_dict(exact)
        result["confidence"] = SCORE_EXACT
        result["basis"] = "exact match in the corpus"
        result["candidates"] = [_candidate_dict(exact, SCORE_EXACT)]
        return result

    # 2. JA4 / JA4S: score the interpretable b- and c-sections.
    if kind_n in JA4_KINDS:
        return _match_ja4(result, kind_n, raw, corpus)

    # 3. no meaningful partial match exists for anything else.
    if kind_n in OPAQUE_KINDS:
        result["basis"] = (
            "no exact match; a {kind} is a single opaque md5, so a partial "
            "match is not meaningful".format(kind=kind_n)
        )
    else:
        result["basis"] = (
            "no exact match; partial matching is only defined for JA4/JA4S"
        )
    return result


def _match_ja4(result: dict, kind: str, raw: str, corpus) -> dict:
    """Fill in *result* by comparing a JA4/JA4S against same-kind entries."""
    query = _sections(raw)
    if query is None:
        result["basis"] = (
            "value is not a well-formed {kind} (expected three "
            "underscore-separated sections)".format(kind=kind)
        )
        return result
    _qa, qb, qc = query

    scored = []  # (score, reason, entry), highest score first after sorting
    for entry in _entries(corpus):
        if _norm(_entry_field(entry, "kind")) != kind:
            continue
        parts = _sections(_entry_field(entry, "value"))
        if parts is None:
            continue
        _ea, eb, ec = parts
        b_hit = qb == eb
        c_hit = qc == ec
        if b_hit and c_hit:
            scored.append((SCORE_B_AND_C,
                           "same cipher list and extension list, different "
                           "a-section", entry))
        elif b_hit:
            scored.append((SCORE_B_ONLY, "same cipher list, different "
                           "extension list", entry))
        elif c_hit:
            scored.append((SCORE_C_ONLY, "same extension list, different "
                           "cipher list", entry))

    if not scored:
        result["basis"] = (
            "no exact match and no shared cipher or extension hash in the corpus"
        )
        return result

    # Highest score first; Python's sort is stable, so equal scores keep corpus
    # order and the result is deterministic.
    scored.sort(key=lambda item: -item[0])
    best_score, best_reason, best_entry = scored[0]
    result["candidates"] = [_candidate_dict(entry, score)
                            for score, _reason, entry in scored[:MAX_CANDIDATES]]
    result["match"] = _match_dict(best_entry)
    result["confidence"] = best_score
    result["basis"] = best_reason
    return result


# --------------------------------------------------------------------------
# match_event
# --------------------------------------------------------------------------
def match_event(event, corpus) -> list:
    """Match every fingerprint on *event*; best confidence first.

    Fingerprints that miss the corpus entirely (confidence ``0.0``) are dropped,
    so an event that matches nothing returns ``[]`` and the best match is simply
    the first element.  The best result is also recorded on the event under
    ``event["best_match"]`` when *event* is a dict.  Never raises.
    """
    if not isinstance(event, dict):
        return []
    fps = event.get("fingerprints")
    if not isinstance(fps, dict):
        fps = {}

    results = []
    for kind in FP_KINDS:
        value = fps.get(kind)
        if not isinstance(value, str) or not value:
            continue
        try:
            res = match_fingerprint(kind, value, corpus)
        except Exception:
            continue
        if res.get("confidence", 0.0) > 0.0:
            results.append(res)

    results.sort(key=lambda r: r.get("confidence", 0.0), reverse=True)
    if results:
        event["best_match"] = results[0]
    return results


# --------------------------------------------------------------------------
# diversity
# --------------------------------------------------------------------------
def _round3(value: float) -> float:
    return round(value, 3)


def diversity(events) -> dict:
    """Summarise how varied each source IP's fingerprinting behaviour is.

    Returns::

        {
          "sources": [ {src_ip, events, distinct_ja4, distinct_ja3, distinct_sni,
                        dominant_ja4, dominant_share, diversity}, ... ],
          "totals": {"sources", "events", "distinct_ja4"},
          "shared_fingerprints": [{kind, value, sources, events}, ...],
        }

    * ``diversity`` is ``distinct_ja4 / events`` rounded to 3 places and capped
      at ``1.0``: a host that presents one fingerprint every time scores near
      ``0``, one that never repeats scores ``1.0``.
    * ``dominant_share`` is the fraction of the source's events carrying its
      most common JA4 (so a monoculture source scores ``1.0``).
    * ``shared_fingerprints`` lists any (kind, value) seen from more than one
      distinct source IP -- the monoculture signal in numbers -- most sources
      first.
    * sources are ordered by event count descending.

    Events with no fingerprints or no ``src_ip`` are tolerated; an event with
    no source cannot be attributed and is left out of the per-source figures.
    """
    if not isinstance(events, (list, tuple)):
        events = []

    src_stats: dict = {}    # src_ip -> accumulator
    fp_sources: dict = {}   # (kind, value) -> set(src_ip)
    fp_events: dict = {}    # (kind, value) -> event count (events with a src)
    all_ja4: set = set()
    total_events = 0

    for event in events:
        if not isinstance(event, dict):
            continue
        total_events += 1

        fps = event.get("fingerprints")
        if not isinstance(fps, dict):
            fps = {}

        src = event.get("src_ip")
        src = src if isinstance(src, str) and src else None

        ja4 = _fp_value(fps, "ja4")
        if ja4:
            all_ja4.add(ja4)

        if src is not None:
            # Shared-fingerprint bookkeeping needs a source to attribute to.
            for kind in FP_KINDS:
                value = _fp_value(fps, kind)
                if not value:
                    continue
                fp_sources.setdefault((kind, value), set()).add(src)
                fp_events[(kind, value)] = fp_events.get((kind, value), 0) + 1

            st = src_stats.get(src)
            if st is None:
                st = {"src_ip": src, "events": 0, "ja4": {}, "ja3": set(),
                      "sni": set()}
                src_stats[src] = st
            st["events"] += 1
            if ja4:
                st["ja4"][ja4] = st["ja4"].get(ja4, 0) + 1
            ja3 = _fp_value(fps, "ja3")
            if ja3:
                st["ja3"].add(ja3)
            sni = event.get("sni")
            if isinstance(sni, str) and sni:
                st["sni"].add(sni)

    sources = []
    for src, st in src_stats.items():
        n = st["events"]
        distinct_ja4 = len(st["ja4"])
        dominant_ja4 = None
        dominant_count = 0
        if st["ja4"]:
            # most common JA4; ties broken by value so the result is stable
            dominant_ja4, dominant_count = max(
                st["ja4"].items(), key=lambda kv: (kv[1], kv[0]))
        sources.append({
            "src_ip": src,
            "events": n,
            "distinct_ja4": distinct_ja4,
            "distinct_ja3": len(st["ja3"]),
            "distinct_sni": len(st["sni"]),
            "dominant_ja4": dominant_ja4,
            "dominant_share": _round3(dominant_count / n) if n else 0.0,
            "diversity": _round3(min(1.0, distinct_ja4 / n)) if n else 0.0,
        })

    sources.sort(key=lambda s: (-s["events"], s["src_ip"]))

    shared = []
    for (kind, value), srcs in fp_sources.items():
        if len(srcs) > 1:
            shared.append({
                "kind": kind,
                "value": value,
                "sources": len(srcs),
                "events": fp_events.get((kind, value), 0),
            })
    shared.sort(key=lambda s: (-s["sources"], -s["events"], s["kind"], s["value"]))

    return {
        "sources": sources,
        "totals": {
            "sources": len(src_stats),
            "events": total_events,
            "distinct_ja4": len(all_ja4),
        },
        "shared_fingerprints": shared,
    }
