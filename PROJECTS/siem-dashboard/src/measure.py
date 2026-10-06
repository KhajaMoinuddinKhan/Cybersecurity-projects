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

from .rules import RuleEngine, rule_matches

__all__ = ["RuleScore", "measure_corpus", "format_scores", "load_corpus"]


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
            "precision": rounded(self.precision),
            "recall": rounded(self.recall),
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
                           techniques=tuple(rule.techniques))
        for rule in engine.rules
    }

    # Which rules fired anywhere in each window, evaluated once per event.
    fired: dict[str, set[str]] = {}
    for index, window in enumerate(windows):
        seen: set[str] = set()
        for event in window["events"]:
            fields = event.get("fields") or {}
            probe = {
                "channel": event.get("channel") or "",
                "event_id": str(event.get("event_id") or ""),
                "level": event.get("level") or "",
                "message": event.get("message") or "",
                "fields": fields,
            }
            for rule in engine.rules:
                if rule.id in seen:
                    continue
                if rule_matches(probe, rule):
                    seen.add(rule.id)
        fired[str(index)] = seen

    for index, window in enumerate(windows):
        label = window["label"]
        for rule in engine.rules:
            score = scores[rule.id]
            named = label in rule.techniques
            did_fire = rule.id in fired[str(index)]
            if named and did_fire:
                score.true_positives += 1
                score.windows_matched.append(label)
            elif named and not did_fire:
                score.false_negatives += 1
                score.windows_missed.append(label)
            elif not named and did_fire:
                score.false_positives += 1
                score.windows_false.append(label)
            else:
                score.true_negatives += 1

    techniques_in_corpus = sorted({label for label in labels if label != "benign"})
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
        def show(value):
            return "  n/a" if value is None else "%.2f" % value
        lines.append("%-46s %-6s %4d %4d %4d %4d %9s %7s %6s" % (
            row["rule_id"][:46], row["severity"][:6], row["tp"], row["fp"], row["fn"],
            row["tn"], show(row["precision"]), show(row["recall"]), show(row["f1"])))

    detected = [r for r in result["rules"] if r["tp"] > 0]
    lines.append("")
    lines.append("%d of %d rules detected anything at all in a corpus of %d windows "
                 "(%d benign, %d technique windows, %d events)."
                 % (len(detected), len(result["rules"]), result["windows"],
                    result["benign_windows"],
                    result["windows"] - result["benign_windows"], result["events"]))
    lines.append("Techniques executed: %s." % ", ".join(result["techniques_in_corpus"]))
    for blocked in result["blocked_techniques"]:
        lines.append("Not executed: %s (%s) -- %s"
                     % (blocked["attack_id"], blocked["name"], blocked["reason"]))
    return "\n".join(lines)
