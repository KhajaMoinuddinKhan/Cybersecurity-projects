"""A learned anomaly detector, and an honest test of whether it survives evasion.

The rest of this project decides whether an event is interesting by matching it
against a rule somebody wrote. That works until the rule does not exist, which is
exactly what the measurement in `src/measure.py` found: not one of the 23 rules
detects any of the five discovery techniques in the corpus. This is the other
approach -- learn what this host normally does, and flag what it does not.

**Isolation forest, written out.** An isolation forest is a set of random
binary trees; each one splits on a random feature at a random value until a
point is alone, and a point that becomes alone quickly is unusual. It is
unsupervised, which is the only option here: there is no labelled attack data to
train on beyond the corpus itself, and training on the corpus would be scoring
the model on what it was taught. So it trains on **benign windows only** and is
then asked about windows it has never seen.

It is written from scratch rather than imported. The project has no machine
learning dependency, the algorithm is a page of arithmetic, and a detector whose
decision can be read back to a path length is one a reader can argue with --
which is the point of the exercise rather than a side effect of it.

**The evasion test is the honest half.** A detector that is only measured on the
data it was built from proves nothing, so the same technique windows are replayed
twice more: once with their features replaced by values drawn from the benign
distribution, and once diluted into a flood of ordinary events. If the detector
falls over, that is the result, and it is reported rather than tuned away.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

__all__ = [
    "FEATURES",
    "FeatureExtractor",
    "IsolationForest",
    "evaluate",
    "evade_by_mimicry",
    "evade_by_dilution",
    "format_report",
]

# The observable properties of an event. Deliberately shallow: these are things
# an attacker can change, which is what makes the evasion test meaningful.
FEATURES = (
    "event_id",
    "channel_index",
    "level_index",
    "message_length",
    "has_network_destination",
    "image_is_system",
    "hour_of_day",
)

_CHANNEL_ORDER = (
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-PowerShell/Operational",
)
_LEVEL_ORDER = ("Information", "Warning", "Error", "Critical", "High", "Medium", "Low")


def _index_of(value: str, order: tuple[str, ...]) -> int:
    try:
        return order.index(value)
    except ValueError:
        return len(order)


def _hour_of(timestamp) -> int:
    text = str(timestamp or "")
    for marker in ("T", " "):
        if marker in text:
            tail = text.split(marker, 1)[1]
            if len(tail) >= 2 and tail[:2].isdigit():
                return int(tail[:2])
    return 0


class FeatureExtractor:
    """Turns a SIEM event into the vector the forest splits on."""

    def vector(self, event: dict) -> list[float]:
        fields = event.get("fields") or {}
        message = str(event.get("message") or "")
        image = str(fields.get("Image") or "")
        destination = fields.get("DestinationIp") or fields.get("DestinationHostname")
        try:
            event_id = float(event.get("event_id") or 0)
        except (TypeError, ValueError):
            event_id = 0.0
        return [
            event_id,
            float(_index_of(str(event.get("channel") or ""), _CHANNEL_ORDER)),
            float(_index_of(str(event.get("level") or ""), _LEVEL_ORDER)),
            float(min(len(message), 2000)),
            1.0 if destination else 0.0,
            1.0 if "\\Windows\\System32" in image else 0.0,
            float(_hour_of(event.get("timestamp"))),
        ]


@dataclass
class _Node:
    feature: int | None = None
    threshold: float = 0.0
    left: "_Node | None" = None
    right: "_Node | None" = None
    size: int = 0

    @property
    def is_leaf(self) -> bool:
        return self.feature is None


class IsolationForest:
    """The usual isolation forest, written out.

    `score` returns the standard normalised anomaly score in (0, 1]: values
    above about 0.5 are unusual, above 0.7 are outliers. The normalisation uses
    the average path length of an unsuccessful search in a binary search tree,
    which is what makes scores comparable across sample sizes.
    """

    def __init__(self, trees: int = 100, sample_size: int = 128, seed: int = 0x5EED):
        self.trees = trees
        self.sample_size = sample_size
        self.random = random.Random(seed)
        self.roots: list[_Node] = []
        self._depth_limit = max(1, int(math.ceil(math.log2(max(2, sample_size)))))

    # -- building ---------------------------------------------------------
    def _build(self, data: list[list[float]], depth: int) -> _Node:
        node = _Node(size=len(data))
        if depth >= self._depth_limit or len(data) <= 1:
            return node
        width = len(data[0])
        candidates = [f for f in range(width) if len({row[f] for row in data}) > 1]
        if not candidates:
            return node
        feature = self.random.choice(candidates)
        values = [row[feature] for row in data]
        low, high = min(values), max(values)
        if low == high:
            return node
        node.feature = feature
        node.threshold = self.random.uniform(low, high)
        left = [row for row in data if row[feature] < node.threshold]
        right = [row for row in data if row[feature] >= node.threshold]
        if not left or not right:
            node.feature = None
            return node
        node.left = self._build(left, depth + 1)
        node.right = self._build(right, depth + 1)
        return node

    def fit(self, vectors: list[list[float]]) -> "IsolationForest":
        if not vectors:
            raise ValueError("an isolation forest needs something to learn from")
        self.roots = []
        for _ in range(self.trees):
            sample = [self.random.choice(vectors)
                      for _ in range(min(self.sample_size, len(vectors)))]
            self.roots.append(self._build(sample, 0))
        return self

    # -- scoring ----------------------------------------------------------
    def _path_length(self, vector: list[float], node: _Node, depth: int) -> float:
        if node.is_leaf:
            # An unsuccessful search in a BST of `size` nodes ends about
            # c(size) deep; adding that is what stops a small leaf looking like
            # a very isolated point.
            return depth + _average_path_length(node.size)
        if vector[node.feature] < node.threshold:
            return self._path_length(vector, node.left, depth + 1)
        return self._path_length(vector, node.right, depth + 1)

    def score(self, vector: list[float]) -> float:
        if not self.roots:
            raise ValueError("fit the forest before scoring with it")
        mean_depth = sum(self._path_length(vector, root, 0) for root in self.roots) / len(self.roots)
        normaliser = _average_path_length(self.sample_size)
        if normaliser <= 0:
            return 0.5
        return 2.0 ** (-mean_depth / normaliser)

    def score_all(self, vectors: list[list[float]]) -> list[float]:
        return [self.score(vector) for vector in vectors]


def _average_path_length(n: int) -> float:
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1) + 0.5772156649) - 2.0 * (n - 1) / n


# -- the experiment ---------------------------------------------------------

def _events(corpus: dict, labels: set[str]) -> list[dict]:
    out = []
    for window in corpus["windows"]:
        if window["label"] in labels:
            out.extend(window["events"])
    return out


def _window_scores(corpus: dict, forest: IsolationForest, extractor: FeatureExtractor) -> dict:
    """The fraction of each window's events the forest calls anomalous."""
    per_window = {}
    for index, window in enumerate(corpus["windows"]):
        vectors = [extractor.vector(event) for event in window["events"]]
        if not vectors:
            per_window[str(index)] = (window["label"], 0.0, 0)
            continue
        scores = forest.score_all(vectors)
        flagged = sum(1 for s in scores if s > 0.5)
        per_window[str(index)] = (window["label"], flagged / len(scores), len(scores))
    return per_window


def evade_by_mimicry(events: list[dict], benign: list[dict], extractor: FeatureExtractor,
                     seed: int = 0xBAD) -> list[dict]:
    """Replace each event's features with values drawn from the benign set.

    This is what "living off the land" looks like to a detector that scores
    observables: the technique still runs, but every feature it is judged on is
    one the host produces anyway. Nothing about the event is falsified beyond
    the fields the detector reads, which is the point -- an attacker does not
    need to hide the event, only to stop it looking distinctive.
    """
    rng = random.Random(seed)
    donors = [extractor.vector(event) for event in benign] or [[0.0] * len(FEATURES)]
    mimicked = []
    for event in events:
        donor = rng.choice(donors)
        clone = dict(event)
        clone["event_id"] = str(int(donor[0]))
        clone["channel"] = _CHANNEL_ORDER[int(donor[1])] if donor[1] < len(_CHANNEL_ORDER) else ""
        clone["level"] = _LEVEL_ORDER[int(donor[2])] if donor[2] < len(_LEVEL_ORDER) else ""
        clone["message"] = "x" * int(donor[3])
        clone["fields"] = dict(event.get("fields") or {})
        if donor[4]:
            clone["fields"]["DestinationIp"] = "203.0.113.9"
        else:
            clone["fields"].pop("DestinationIp", None)
        clone["fields"]["Image"] = (r"C:\Windows\System32\svchost.exe" if donor[5]
                                    else r"C:\Program Files\App\app.exe")
        mimicked.append(clone)
    return mimicked


def evade_by_dilution(events: list[dict], benign: list[dict], factor: int = 10,
                      seed: int = 0xD11) -> list[dict]:
    """Bury the technique's events in a flood of ordinary ones.

    A detector with a fixed score threshold is not diluted by this, because the
    threshold does not move. A detector that flags the top N per cent of a window
    is, and that difference is worth measuring rather than assuming.
    """
    rng = random.Random(seed)
    flood = [rng.choice(benign) for _ in range(len(events) * factor)] if benign else []
    return list(events) + flood


def evaluate(corpus: dict, threshold: float = 0.5) -> dict:
    """Train on benign windows, then score every window, clean and evaded."""
    extractor = FeatureExtractor()
    benign = _events(corpus, {"benign"})
    technique_labels = {w["label"] for w in corpus["windows"] if w["label"] != "benign"}
    attacks = _events(corpus, technique_labels)
    if not benign or not attacks:
        raise ValueError("the corpus needs both benign and technique windows")

    forest = IsolationForest().fit([extractor.vector(event) for event in benign])

    def summarise(name: str, windows: dict) -> dict:
        benign_scores, attack_scores = [], []
        for label, fraction, count in windows.values():
            (benign_scores if label == "benign" else attack_scores).append(fraction)
        mean = lambda xs: (sum(xs) / len(xs)) if xs else 0.0
        return {
            "name": name,
            "benign_windows": len(benign_scores),
            "attack_windows": len(attack_scores),
            "mean_flagged_benign": round(mean(benign_scores), 3),
            "mean_flagged_attack": round(mean(attack_scores), 3),
            "separation": round(mean(attack_scores) - mean(benign_scores), 3),
        }

    clean = summarise("clean", _window_scores(corpus, forest, extractor))

    # The evasions are scored by putting the mimicked or diluted events back
    # into a copy of the corpus, so the same code path scores all three.
    def rescore(name: str, replacement: list[dict], label: str) -> dict:
        copy = {"windows": []}
        for window in corpus["windows"]:
            if window["label"] == label:
                copy["windows"].append({**window, "events": replacement})
            else:
                copy["windows"].append(window)
        return summarise(name, _window_scores(copy, forest, extractor))

    results = [clean]
    for label in sorted(technique_labels):
        events = [e for w in corpus["windows"] if w["label"] == label for e in w["events"]]
        if not events:
            continue
        results.append(rescore("mimicry (%s)" % label,
                               evade_by_mimicry(events, benign, extractor), label))
        results.append(rescore("dilution (%s)" % label,
                               evade_by_dilution(events, benign), label))

    surviving = [r for r in results[1:] if r["separation"] >= clean["separation"] * 0.5]
    return {
        "threshold": threshold,
        "features": list(FEATURES),
        "trained_on_events": len(benign),
        "results": results,
        "survived": len(surviving),
        "attempts": len(results) - 1,
    }


def format_report(result: dict) -> str:
    lines = [
        "An isolation forest trained on %d benign events, %d features." % (
            result["trained_on_events"], len(result["features"])),
        "",
        "%-30s %8s %9s %11s" % ("scenario", "benign", "attack", "separation"),
        "-" * 62,
    ]
    for row in result["results"]:
        lines.append("%-30s %8.3f %9.3f %11.3f" % (
            row["name"][:30], row["mean_flagged_benign"], row["mean_flagged_attack"],
            row["separation"]))
    lines.append("")
    lines.append("separation is the mean fraction of events flagged anomalous: attack minus benign.")
    lines.append("%d of %d evasion attempts left at least half the separation intact."
                 % (result["survived"], result["attempts"]))
    return "\n".join(lines)
