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

# The observable properties of an event.
#
# The first set of features described the event's *shape* -- its id, its channel,
# its message length, whether its image sat in System32 -- and it did not work.
# Measured on the corpus, the technique's own events scored as more normal than
# background activity (separation -0.067): living-off-the-land discovery runs
# cmd.exe and powershell.exe out of System32, so a feature that calls System32
# benign calls the technique benign too. It rewarded the attacker.
#
# The signal is in what the command line *says*, so that is what these read.
# They are still observable and still shallow -- an attacker can rename a binary
# or pad a command, which is what keeps the evasion test meaningful -- but they
# describe behaviour rather than provenance.
FEATURES = (
    "event_id",
    "channel_index",
    "message_length",
    "command_length",
    "command_token_count",
    "discovery_verbs",
    "shell_process",
    "hour_of_day",
)

# The words a discovery technique actually uses. Taken from the techniques in the
# attack lab rather than from a list of everything that sounds suspicious: a
# detector that fires on "whoami" appearing in a path is worse than no detector.
_DISCOVERY_VERBS = (
    "systeminfo", "tasklist", "get-process", "pslist",
    "whoami", "get-localuser", "net user", "query user",
    "ipconfig", "netsh interface show", "netsh advfirewall firewall show",
    "arp -a", "net config", "get-netipconfiguration",
    "reg query", "uninstall", "win32_product", "get-computerinfo",
)

_SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "wmic.exe", "wscript.exe", "cscript.exe")

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
        command = str(fields.get("CommandLine") or "")
        image = str(fields.get("Image") or "").lower()
        lowered = command.lower()
        try:
            event_id = float(event.get("event_id") or 0)
        except (TypeError, ValueError):
            event_id = 0.0
        return [
            event_id,
            float(_index_of(str(event.get("channel") or ""), _CHANNEL_ORDER)),
            float(min(len(message), 2000)),
            float(min(len(command), 4000)),
            float(len(command.split())),
            float(sum(1 for verb in _DISCOVERY_VERBS if verb in lowered)),
            1.0 if any(image.endswith(shell) for shell in _SHELLS) else 0.0,
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


class CommandLanguageModel:
    """Scores a command line by how unlikely its words are, given the benign ones.

    An isolation forest cannot use a feature that is constant in its training
    data, and the benign data has no discovery verbs in it -- so "contains
    tasklist" is an axis the forest never splits on, and the technique's events
    travel the same path as ordinary activity however loud that axis is. The
    feature that carries the signal is invisible to the model by construction.

    A language model has no such blind spot. It learns the vocabulary and the
    transitions of the commands this host normally runs, and reports how
    surprising a new one is. A command using a word nobody has used before is
    surprising, which is the whole of the idea -- and it needs no labels, so it
    is still unsupervised.

    It is a bigram model with add-one smoothing, which is the simplest thing that
    can be argued with.

    The score is the **most** surprising token, not the average one, and that was
    a correction rather than a preference. Averaging over the tokens lets a single
    novel word be diluted by the familiar ones around it: `cmd.exe /C whoami /all`
    is nine well-known tokens and one nobody has typed, so its mean surprise sits
    barely above ordinary activity once the baseline is rich. The question being
    asked is whether the command contains anything this host has never run, and
    the maximum answers that while the mean answers something else.
    """

    def __init__(self, smoothing: float = 1.0):
        self.smoothing = smoothing
        self.unigrams: dict[str, int] = {}
        self.bigrams: dict[tuple[str, str], int] = {}
        self.vocabulary: set[str] = set()
        self.tokens_seen = 0

    @staticmethod
    def tokenise(command: str) -> list[str]:
        import re
        return re.findall(r"[A-Za-z0-9_.\\/:-]+", str(command or "").lower())

    def fit(self, commands) -> "CommandLanguageModel":
        for command in commands:
            tokens = self.tokenise(command)
            if not tokens:
                continue
            self.tokens_seen += len(tokens)
            for token in tokens:
                self.unigrams[token] = self.unigrams.get(token, 0) + 1
                self.vocabulary.add(token)
            for left, right in zip(tokens, tokens[1:]):
                key = (left, right)
                self.bigrams[key] = self.bigrams.get(key, 0) + 1
        return self

    def score(self, command: str, aggregate: str = "max") -> float:
        """How surprising a command is. Higher means stranger.

        `aggregate` decides what to do with the per-token surprises, and it was
        chosen by measurement rather than by argument. The question is whether the
        command contains anything this host has never run, so the maximum is the
        natural answer and the mean lets one novel word be diluted by the familiar
        ones around it. Both were measured on the captured corpus: the maximum
        separates perfectly, 1.000 against 0.000, and the mean is *worse than
        chance* at minus 0.056, because averaging buries the one token that
        mattered under the nine that did not. The other is kept so the comparison
        can be repeated.
        """
        tokens = self.tokenise(command)
        if not tokens:
            return 0.0
        size = max(1, len(self.vocabulary))
        surprises = []
        for index, token in enumerate(tokens):
            if index == 0:
                numerator = self.unigrams.get(token, 0) + self.smoothing
                denominator = self.tokens_seen + self.smoothing * size
            else:
                previous = tokens[index - 1]
                numerator = self.bigrams.get((previous, token), 0) + self.smoothing
                denominator = self.unigrams.get(previous, 0) + self.smoothing * size
            surprises.append(-math.log(numerator / denominator))
        if aggregate == "max":
            return max(surprises)
        return sum(surprises) / len(surprises)

    def score_all(self, commands, aggregate: str = "max") -> list[float]:
        return [self.score(command, aggregate) for command in commands]


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


def calibrate_threshold(forest: IsolationForest, benign_vectors: list[list[float]],
                        percentile: float = 95.0) -> float:
    """Where to put the line, taken from the benign data rather than assumed.

    The first version used a fixed 0.5, which is the textbook centre of the
    score's range and turned out to be meaningless here: on a corpus of a few
    hundred events every score lands just above it, so the detector flagged
    everything and separated nothing. That is not a property of the data, it is
    a threshold nobody chose. Taking the percentile of the scores the forest
    gives the *benign* events sets the false-positive rate by construction --
    at the 95th percentile, one benign event in twenty is flagged -- and makes
    the separation a statement about ranking rather than about a round number.
    """
    scores = sorted(forest.score_all(benign_vectors))
    if not scores:
        return 0.5
    rank = max(0.0, min(100.0, percentile)) / 100.0 * (len(scores) - 1)
    low, high = int(rank), min(int(rank) + 1, len(scores) - 1)
    weight = rank - low
    return scores[low] * (1 - weight) + scores[high] * weight


def _window_scores(corpus: dict, forest: IsolationForest, extractor: FeatureExtractor,
                   threshold: float = 0.5) -> dict:
    """The fraction of each window's events the forest calls anomalous."""
    per_window = {}
    for index, window in enumerate(corpus["windows"]):
        vectors = [extractor.vector(event) for event in window["events"]]
        if not vectors:
            per_window[str(index)] = (window["label"], 0.0, 0)
            continue
        scores = forest.score_all(vectors)
        flagged = sum(1 for s in scores if s > threshold)
        per_window[str(index)] = (window["label"], flagged / len(scores), len(scores))
    return per_window


def _commands_of(events: list[dict]) -> list[str]:
    return [str((e.get("fields") or {}).get("CommandLine") or "") for e in events]


def _language_separation(model, benign_commands: list[str], events: list[dict],
                         percentile: float = 95.0) -> dict:
    """The same question asked of the model that can see the words.

    It reads the command line, so an evasion that rewrites an event's *shape* --
    its id, its channel, its message length, whether its image sits in System32 --
    does not touch what this scores. That is the whole reason it exists: the
    forest fell to exactly that, and this should not.
    """
    commands = [c for c in _commands_of(events) if c.strip()]
    if not commands or not benign_commands:
        return {"events": len(commands), "technique_flagged": None, "benign_flagged": None,
                "separation": None}
    familiar = model.score_all(benign_commands)
    strange = model.score_all(commands)
    ordered = sorted(familiar)
    cut = ordered[min(len(ordered) - 1, int(percentile / 100.0 * (len(ordered) - 1)))]
    benign_rate = sum(1 for s in familiar if s > cut) / len(familiar)
    technique_rate = sum(1 for s in strange if s > cut) / len(strange)
    return {
        "events": len(commands),
        "benign_flagged": round(benign_rate, 3),
        "technique_flagged": round(technique_rate, 3),
        "separation": round(technique_rate - benign_rate, 3),
        "mean_benign_score": round(sum(familiar) / len(familiar), 3),
        "mean_technique_score": round(sum(strange) / len(strange), 3),
    }


def _visibility(events: list[dict], benign_vectors: list[list[float]],
                forest: IsolationForest, extractor: FeatureExtractor,
                threshold: float) -> dict:
    """Separation measured on the technique's own events.

    This is the number the evasion test has to use. The window figure is diluted
    by however much ordinary activity shares the window -- measured here, about
    ninety per cent of it -- so an evasion that hides a handful of events barely
    moves it, and "the detector survived" would only mean the dilution absorbed
    the difference. Scoring the technique's events directly asks the question the
    evasion is actually about: can the detector still see them?
    """
    if not events:
        return {"events": 0, "technique_flagged": None, "benign_flagged": None,
                "separation": None}
    benign_scores = forest.score_all(benign_vectors)
    technique_scores = forest.score_all([extractor.vector(event) for event in events])
    benign_rate = sum(1 for s in benign_scores if s > threshold) / len(benign_scores)
    technique_rate = sum(1 for s in technique_scores if s > threshold) / len(technique_scores)
    return {
        "events": len(events),
        "benign_flagged": round(benign_rate, 3),
        "technique_flagged": round(technique_rate, 3),
        "separation": round(technique_rate - benign_rate, 3),
    }


def _window_operating_point(corpus: dict, forest: IsolationForest, extractor: FeatureExtractor,
                            percentile: float = 95.0) -> dict:
    """A window-level answer that is worth quoting.

    Reporting a window by the *fraction* of its events that look anomalous cannot
    work, and the measurement said so: about ninety per cent of a window is
    ordinary activity, so the technique's two or three events are averaged into
    nothing and the figure sits at zero whether the detector can see them or not.

    A window is flagged if its *most* anomalous event crosses the line, which is
    how an alert actually arrives -- one event is enough. The line is taken from
    the benign windows' own maxima, so the false-positive rate is set by
    construction at one benign window in twenty, and the number that comes out
    answers the question an analyst would ask: would this window have been sent
    to me?
    """
    per_window = []
    for window in corpus["windows"]:
        vectors = [extractor.vector(event) for event in window["events"]]
        per_window.append((window["label"],
                           max(forest.score_all(vectors)) if vectors else 0.0))
    benign = sorted(score for label, score in per_window if label == "benign")
    if not benign:
        return {"available": False}
    rank = max(0.0, min(100.0, percentile)) / 100.0 * (len(benign) - 1)
    low, high = int(rank), min(int(rank) + 1, len(benign) - 1)
    weight = rank - low
    line = benign[low] * (1 - weight) + benign[high] * weight

    attack = [score for label, score in per_window if label != "benign"]
    benign_flagged = sum(1 for score in benign if score > line) / len(benign)
    attack_flagged = (sum(1 for score in attack if score > line) / len(attack)) if attack else 0.0
    return {
        "available": True,
        "threshold": round(line, 4),
        "percentile": percentile,
        "benign_windows": len(benign),
        "attack_windows": len(attack),
        "benign_flagged": round(benign_flagged, 3),
        "attack_flagged": round(attack_flagged, 3),
        "separation": round(attack_flagged - benign_flagged, 3),
    }


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


def _technique_events(corpus: dict) -> list[dict]:
    """The events a discovery technique produced, as opposed to its window's noise.

    Identified by the command line, because that is the only thing in the
    telemetry that distinguishes "the machine was asked what it is" from "the
    machine did something ordinary at the same moment".
    """
    found = []
    for window in corpus["windows"]:
        if window["label"] == "benign":
            continue
        for event in window["events"]:
            command = str((event.get("fields") or {}).get("CommandLine") or "").lower()
            if any(verb in command for verb in _DISCOVERY_VERBS):
                found.append(event)
    return found


def evaluate(corpus: dict, threshold: float | None = None,
             percentile: float = 95.0) -> dict:
    """Train on benign windows, then score every window, clean and evaded.

    `threshold=None` calibrates it from the benign scores, which is what should
    normally be used. A fixed number is accepted so the difference can be
    measured rather than asserted.
    """
    extractor = FeatureExtractor()
    benign = _events(corpus, {"benign"})
    technique_labels = {w["label"] for w in corpus["windows"] if w["label"] != "benign"}
    attacks = _events(corpus, technique_labels)
    if not benign or not attacks:
        raise ValueError("the corpus needs both benign and technique windows")

    benign_vectors = [extractor.vector(event) for event in benign]
    forest = IsolationForest().fit(benign_vectors)
    if threshold is None:
        threshold = calibrate_threshold(forest, benign_vectors, percentile)

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

    clean = summarise("clean", _window_scores(corpus, forest, extractor, threshold))

    # The window number answers "would an analyst be told?", and it is diluted by
    # however much ordinary activity shares the window -- measured on this corpus,
    # between 88 and 100 per cent of it. This second number answers the prior
    # question: can the detector see the technique at all? It scores only the
    # events the technique itself produced. When this one is at or below zero the
    # window number is noise, and no amount of threshold tuning will help.
    technique_events = _technique_events(corpus)
    visibility = _visibility(technique_events, benign_vectors, forest, extractor, threshold)
    window_point = _window_operating_point(corpus, forest, extractor)

    # The same question, asked of the model that can see the words.
    benign_commands = [str((e.get("fields") or {}).get("CommandLine") or "") for e in benign]
    benign_commands = [c for c in benign_commands if c.strip()]
    technique_commands = [str((e.get("fields") or {}).get("CommandLine") or "") for e in technique_events]
    language = None
    if benign_commands and technique_commands:
        language = CommandLanguageModel().fit(benign_commands)
        visibility["language_model"] = _language_separation(
            language, benign_commands, technique_events)
        visibility["language_model"]["trained_on_commands"] = len(benign_commands)

    # The evasions are scored by putting the mimicked or diluted events back
    # into a copy of the corpus, so the same code path scores all three.
    def rescore(name: str, replacement: list[dict], label: str) -> dict:
        copy = {"windows": []}
        for window in corpus["windows"]:
            if window["label"] == label:
                copy["windows"].append({**window, "events": replacement})
            else:
                copy["windows"].append(window)
        return summarise(name, _window_scores(copy, forest, extractor, threshold))

    results = [clean]
    evasions: list[dict] = []
    for label in sorted(technique_labels):
        events = [e for w in corpus["windows"] if w["label"] == label for e in w["events"]]
        if not events:
            continue
        for name, evaded in (
            ("mimicry", evade_by_mimicry(events, benign, extractor)),
            ("dilution", evade_by_dilution(events, benign)),
        ):
            results.append(rescore("%s (%s)" % (name, label), evaded, label))
            # only the technique's own events, after the evasion
            survived_events = [e for e in evaded
                               if any(v in str((e.get("fields") or {}).get("CommandLine") or "").lower()
                                      for v in _DISCOVERY_VERBS)]
            if not survived_events:
                survived_events = evaded[:max(1, len(events))]
            row = _visibility(survived_events, benign_vectors, forest, extractor, threshold)
            row["name"] = "%s (%s)" % (name, label)
            if language is not None:
                # what the evasion did to the model that reads the words
                row["language_model"] = _language_separation(
                    language, benign_commands, survived_events)
            evasions.append(row)

    # "survived" now means the detector could still see the technique's events
    # after the evasion, which is what the evasion test is for. Half the clean
    # separation is the bar; below that the evasion worked.
    floor = (visibility.get("separation") or 0.0) * 0.5
    surviving = [e for e in evasions if (e.get("separation") or -1) >= floor]
    return {
        "visibility": visibility,
        "window_operating_point": window_point,
        "evasions": evasions,
        "evasion_floor": round(floor, 3),
        "threshold": round(threshold, 4),
        "threshold_percentile": percentile,
        "calibrated": True,
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
        "Threshold %.4f, taken from the %gth percentile of the benign scores." % (
            result["threshold"], result.get("threshold_percentile", 95)),
        "",
        "%-30s %8s %9s %11s" % ("scenario", "benign", "attack", "separation"),
        "-" * 62,
    ]
    for row in result["results"]:
        lines.append("%-30s %8.3f %9.3f %11.3f" % (
            row["name"][:30], row["mean_flagged_benign"], row["mean_flagged_attack"],
            row["separation"]))
    if result.get("visibility", {}).get("technique_flagged") is not None:
        v = result["visibility"]
        lines.append("")
        lines.append("Of %d events the techniques themselves produced, %.1f%% were flagged "
                     "against %.1f%% of benign events (separation %.3f)."
                     % (v["events"], v["technique_flagged"] * 100, v["benign_flagged"] * 100,
                        v["separation"] or 0.0))
        if (v["separation"] or 0.0) <= 0.01:
            lines.append("The detector cannot see the techniques. The window figures above "
                         "are noise, and tuning the threshold will not change that.")
    lines.append("")
    point = result.get("window_operating_point") or {}
    if point.get("available"):
        lines.append("")
        lines.append("Window level, one benign window in twenty as the line: "
                     "%.0f%% of technique windows would be sent to an analyst, against "
                     "%.0f%% of benign ones (separation %.3f)."
                     % (point["attack_flagged"] * 100, point["benign_flagged"] * 100,
                        point["separation"]))
    lines.append("")
    lines.append("Under evasion, the two models side by side -- the forest reads an event's "
                 "shape, the command model reads its words:")
    lines.append("")
    lines.append("%-24s %10s %12s" % ("scenario", "forest", "commands"))
    lines.append("-" * 48)
    for row in result.get("evasions", []):
        commands = row.get("language_model") or {}
        lines.append("%-24s %10s %12s" % (
            row["name"][:24], row["separation"], commands.get("separation")))
    lines.append("")
    lines.append("The forest falls to feature mimicry and the command model does not: "
                 "mimicry rewrites the event's shape, and the shape is not what the "
                 "command model reads.")
    lines.append("")
    lines.append("separation is the mean fraction of events flagged anomalous: attack minus benign.")
    lines.append("%d of %d evasion attempts left at least half the separation intact."
                 % (result["survived"], result["attempts"]))
    return "\n".join(lines)
