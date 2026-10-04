"""Threat-intel corpus loader for TLS fingerprints.

Loads one or more JSON files of fingerprint entries and exposes exact-match
lookup plus aggregate statistics. Malformed or unreadable files are skipped
(and recorded on ``Corpus.skipped``) rather than raising.
"""
from __future__ import annotations

import glob
import json
import os
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Entry:
    kind: str
    value: str
    category: str
    name: str
    source: str
    license: str

    def as_dict(self) -> dict:
        return asdict(self)


def _norm(s) -> str:
    return str(s).strip().lower()


class Corpus:
    """A collection of fingerprint entries with exact-match lookup."""

    def __init__(self, entries=None, skipped=None):
        self._entries: list[Entry] = list(entries or [])
        self.skipped: list[dict] = list(skipped or [])
        # index: (kind, value) -> first Entry with that key
        self._index: dict[tuple[str, str], Entry] = {}
        for e in self._entries:
            key = (e.kind, e.value)
            self._index.setdefault(key, e)

    def match(self, kind: str, value: str) -> Optional[Entry]:
        """Exact match on normalised (lowercased, stripped) kind and value."""
        return self._index.get((_norm(kind), _norm(value)))

    def entries(self) -> list[Entry]:
        return list(self._entries)

    def stats(self) -> dict:
        # group by source, preserving first-seen order
        src_order: list[str] = []
        src_map: dict[str, dict] = {}
        for e in self._entries:
            if e.source not in src_map:
                src_map[e.source] = {"name": e.source, "license": e.license,
                                     "records": 0, "kinds": []}
                src_order.append(e.source)
            s = src_map[e.source]
            s["records"] += 1
            if e.kind not in s["kinds"]:
                s["kinds"].append(e.kind)
        sources = []
        for name in src_order:
            s = src_map[name]
            sources.append({
                "name": s["name"],
                "kind": ",".join(sorted(s["kinds"])),
                "license": s["license"],
                "records": s["records"],
            })

        cat_map: dict[str, int] = {}
        for e in self._entries:
            cat_map[e.category] = cat_map.get(e.category, 0) + 1
        by_category = [{"category": c, "records": n}
                       for c, n in sorted(cat_map.items())]

        return {"sources": sources, "by_category": by_category,
                "total": len(self._entries)}


def load_corpus(dir: str) -> Corpus:
    """Load every ``*.json`` file in *dir* into a :class:`Corpus`.

    A file that is missing, unreadable, or not valid JSON is skipped and the
    reason recorded in ``Corpus.skipped``.
    """
    entries: list[Entry] = []
    skipped: list[dict] = []

    try:
        paths = sorted(glob.glob(os.path.join(dir, "*.json")))
    except Exception as exc:  # pragma: no cover - defensive
        paths = []
        skipped.append({"file": dir, "error": repr(exc)})

    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            skipped.append({"file": path, "error": f"{type(exc).__name__}: {exc}"})
            continue

        if not isinstance(data, list):
            skipped.append({"file": path, "error": "top-level JSON is not a list"})
            continue

        for raw in data:
            if not isinstance(raw, dict):
                skipped.append({"file": path, "error": "entry is not an object"})
                continue
            try:
                entry = Entry(
                    kind=_norm(raw["kind"]),
                    value=_norm(raw["value"]),
                    category=_norm(raw.get("category", "")),
                    name=str(raw.get("name", "")),
                    source=str(raw.get("source", "")),
                    license=str(raw.get("license", "")),
                )
            except KeyError as exc:
                skipped.append({"file": path, "error": f"missing field {exc}"})
                continue
            if not entry.kind or not entry.value:
                skipped.append({"file": path, "error": "empty kind or value"})
                continue
            entries.append(entry)

    return Corpus(entries, skipped)
