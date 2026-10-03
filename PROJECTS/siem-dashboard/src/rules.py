"""Detection and correlation rules as data, and the engine that evaluates them.

A rule lives in a file, not in Python. It declares what it looks for and what a
match means, which is what makes it possible to score a rule on its own against
labelled attack data. Nothing about a detection is hard-coded here.

Rules are read from ``src/rules/*.yml`` and ``src/rules/*.json``. The YAML form
follows the Sigma convention closely enough that a rule written for Sigma is
recognisable, but this engine implements a documented subset rather than all of
Sigma. The README lists exactly which modifiers and operators are supported.

Two kinds of rule live in the same directory:

``type: detection`` (the default)
    Evaluated against one event at a time.

``type: correlation``
    Evaluated against a sequence of alerts on the same host or user inside a
    time window. This is the part a single-event rule cannot express.
"""
from __future__ import annotations

import ipaddress
import json
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

try:  # PyYAML is required for .yml rules; JSON rules work without it.
    import yaml
except ImportError:  # pragma: no cover - exercised by the JSON-only path
    yaml = None


RULE_DIR = Path(__file__).resolve().parent / "rules"

VALID_LEVELS = ("High", "Medium", "Low")

# Modifiers that change how a value is compared. ``all`` is a combinator rather
# than a comparison, but it belongs to the same namespace in a rule file.
MODIFIERS = {"contains", "startswith", "endswith", "re", "in", "all", "cidr"}

# logsource keys are treated as an implicit condition, the way Sigma treats
# them: a rule for the Security channel does not fire on a Sysmon event.
LOGSOURCE_FIELDS = ("channel", "event_id", "provider", "source")


class RuleError(ValueError):
    """A rule file is present but cannot be used."""


@dataclass(frozen=True)
class Rule:
    """One single-event detection, loaded from a file."""

    id: str
    title: str
    level: str
    detection: dict[str, Any]
    condition: str
    tags: tuple[str, ...] = ()
    logsource: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    falsepositives: tuple[str, ...] = ()
    source_file: str = ""

    @property
    def techniques(self) -> tuple[str, ...]:
        """ATT&CK technique identifiers carried in the rule's tags."""

        return tuple(
            tag for tag in self.tags if re.fullmatch(r"attack\.t\d+(?:\.\d+)?", tag)
        )


@dataclass(frozen=True)
class CorrelationRule:
    """A rule that fires on an ordered sequence of alerts."""

    id: str
    title: str
    level: str
    steps: tuple[str, ...]
    group_by: str = "host"
    window_seconds: int = 300
    min_steps: int = 2
    tags: tuple[str, ...] = ()
    description: str = ""
    falsepositives: tuple[str, ...] = ()
    source_file: str = ""

    @property
    def techniques(self) -> tuple[str, ...]:
        return tuple(
            tag for tag in self.tags if re.fullmatch(r"attack\.t\d+(?:\.\d+)?", tag)
        )


def event_fields(payload: dict[str, Any]) -> dict[str, str]:
    """Flatten an event into the field names a rule can match on.

    Structured EventData keys are exposed twice: once bare, so a rule can say
    ``CommandLine``, and once namespaced, so a rule can be explicit about where
    the value came from with ``data.CommandLine``.
    """

    fields: dict[str, str] = {}
    for name in (
        "channel",
        "event_id",
        "provider",
        "level",
        "severity",
        "username",
        "host",
        "source_ip",
        "source",
        "message",
        "rule_name",
    ):
        value = payload.get(name)
        fields[name] = "" if value is None else str(value)

    data = payload.get("fields") or {}
    if isinstance(data, dict):
        for key, value in data.items():
            text = "" if value is None else str(value)
            fields[f"data.{key}"] = text
            fields.setdefault(str(key), text)

    return fields


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _match_one(field_value: str, expected: Any, modifier: str | None) -> bool:
    actual = field_value
    wanted = _text(expected)

    if modifier is None:
        return actual.strip().lower() == wanted.strip().lower()
    if modifier == "contains":
        return wanted.strip().lower() in actual.lower()
    if modifier == "startswith":
        return actual.strip().lower().startswith(wanted.strip().lower())
    if modifier == "endswith":
        return actual.strip().lower().endswith(wanted.strip().lower())
    if modifier == "re":
        try:
            return re.search(wanted, actual, re.IGNORECASE) is not None
        except re.error as exc:
            raise RuleError(f"Invalid regular expression {wanted!r}: {exc}") from exc
    if modifier == "cidr":
        try:
            network = ipaddress.ip_network(wanted, strict=False)
            address = ipaddress.ip_address(actual.strip())
        except ValueError:
            return False
        return address in network
    raise RuleError(f"Unsupported modifier: {modifier}")


def _match_selection(fields: dict[str, str], selection: dict[str, Any]) -> bool:
    """Evaluate one named selection block against an event."""

    for key, expected in selection.items():
        parts = key.split("|")
        name = parts[0]
        modifiers = parts[1:]
        unknown = [item for item in modifiers if item not in MODIFIERS]
        if unknown:
            raise RuleError(f"Unsupported modifier(s) in {key!r}: {', '.join(unknown)}")

        actual = fields.get(name, "")
        values = _as_list(expected)
        require_all = "all" in modifiers
        effective = [item for item in modifiers if item != "all"]
        if len(effective) > 1:
            raise RuleError(f"Only one matching modifier is supported per field: {key!r}")
        modifier = effective[0] if effective else None

        results = [_match_one(actual, value, modifier) for value in values]
        if require_all:
            if not all(results):
                return False
        elif not any(results):
            return False

    return True


def _tokenise(condition: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", condition or "")


def _parse_condition(tokens: list[str]) -> Any:
    """Parse ``and`` / ``or`` / ``not`` with parentheses into a small tree."""

    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        token = tokens[position]
        position += 1
        return token

    def parse_or() -> Any:
        node = parse_and()
        while peek() is not None and peek().lower() == "or":
            take()
            node = ("or", node, parse_and())
        return node

    def parse_and() -> Any:
        node = parse_not()
        while peek() is not None and peek().lower() == "and":
            take()
            node = ("and", node, parse_not())
        return node

    def parse_not() -> Any:
        if peek() is not None and peek().lower() == "not":
            take()
            return ("not", parse_not())
        return parse_atom()

    def parse_atom() -> Any:
        token = peek()
        if token is None:
            raise RuleError("Rule condition ends unexpectedly")
        if token == "(":
            take()
            node = parse_or()
            if peek() != ")":
                raise RuleError("Rule condition has an unclosed parenthesis")
            take()
            return node
        if token == ")":
            raise RuleError("Rule condition has an unexpected closing parenthesis")
        return ("ref", take())

    tree = parse_or()
    if position != len(tokens):
        raise RuleError(
            f"Rule condition has trailing tokens: {' '.join(tokens[position:])}"
        )
    return tree


def _evaluate(tree: Any, selections: dict[str, bool]) -> bool:
    kind = tree[0]
    if kind == "ref":
        name = tree[1]
        if name not in selections:
            raise RuleError(f"Rule condition refers to unknown selection {name!r}")
        return selections[name]
    if kind == "not":
        return not _evaluate(tree[1], selections)
    if kind == "and":
        return _evaluate(tree[1], selections) and _evaluate(tree[2], selections)
    if kind == "or":
        return _evaluate(tree[1], selections) or _evaluate(tree[2], selections)
    raise RuleError(f"Unsupported condition node: {kind}")


def _logsource_matches(fields: dict[str, str], rule: Rule) -> bool:
    """Apply logsource keys as an implicit condition."""

    for name in LOGSOURCE_FIELDS:
        expected = rule.logsource.get(name)
        if expected in (None, ""):
            continue
        if fields.get(name, "").strip().lower() != _text(expected).strip().lower():
            return False
    return True


def _selections(fields: dict[str, str], rule: Rule) -> dict[str, bool]:
    selections: dict[str, bool] = {}
    for name, selection in rule.detection.items():
        if name == "condition":
            continue
        if not isinstance(selection, dict):
            raise RuleError(f"Selection {name!r} in rule {rule.id!r} must be a mapping")
        selections[name] = _match_selection(fields, selection)
    return selections


def matched_conditions(fields: dict[str, str], rule: Rule) -> list[str]:
    """Return the names of the selections that matched, for the alert record."""

    return [name for name, hit in _selections(fields, rule).items() if hit]


def rule_matches(fields: dict[str, str], rule: Rule) -> bool:
    """True when the rule's logsource and condition are satisfied."""

    if not _logsource_matches(fields, rule):
        return False
    tree = _parse_condition(_tokenise(rule.condition))
    return _evaluate(tree, _selections(fields, rule))


def _load_mapping(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yml", ".yaml"}:
        if yaml is None:
            raise RuleError(
                f"{path.name} needs PyYAML. Run: python -m pip install -r requirements.txt"
            )
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise RuleError(f"{path.name} is not valid YAML: {exc}") from exc
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuleError(f"{path.name} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise RuleError(f"{path.name} must contain a single rule object")
    return data


def _level_of(raw: dict[str, Any], source_file: str) -> str:
    level = str(raw.get("level") or "Low").strip().title()
    if level not in VALID_LEVELS:
        raise RuleError(
            f"{source_file}: level must be High, Medium, or Low (got {raw.get('level')!r})"
        )
    return level


def _build_rule(raw: dict[str, Any], source_file: str) -> Rule:
    detection = raw.get("detection")
    if not isinstance(detection, dict) or not detection:
        raise RuleError(f"{source_file}: a rule needs a detection block")

    condition = detection.get("condition")
    if not condition:
        raise RuleError(f"{source_file}: a rule needs detection.condition")

    rule_id = str(raw.get("id") or "").strip()
    if not rule_id:
        raise RuleError(f"{source_file}: a rule needs an id")

    return Rule(
        id=rule_id,
        title=str(raw.get("title") or rule_id).strip(),
        level=_level_of(raw, source_file),
        detection=detection,
        condition=str(condition),
        tags=tuple(str(tag) for tag in _as_list(raw.get("tags") or [])),
        logsource=raw.get("logsource") or {},
        description=str(raw.get("description") or "").strip(),
        falsepositives=tuple(str(item) for item in _as_list(raw.get("falsepositives") or [])),
        source_file=source_file,
    )


def _build_correlation(raw: dict[str, Any], source_file: str) -> CorrelationRule:
    steps = raw.get("steps")
    if not isinstance(steps, list) or len(steps) < 2:
        raise RuleError(f"{source_file}: a correlation rule needs at least two steps")

    step_ids: list[str] = []
    for step in steps:
        if isinstance(step, dict):
            step_id = str(step.get("rule") or "").strip()
        else:
            step_id = str(step).strip()
        if not step_id:
            raise RuleError(f"{source_file}: every step needs a rule id")
        step_ids.append(step_id)

    rule_id = str(raw.get("id") or "").strip()
    if not rule_id:
        raise RuleError(f"{source_file}: a correlation rule needs an id")

    window = raw.get("window_seconds", 300)
    if not isinstance(window, int) or window <= 0:
        raise RuleError(f"{source_file}: window_seconds must be a positive whole number")

    group_by = str(raw.get("group_by") or "host").strip()
    if group_by not in {"host", "username", "source_ip"}:
        raise RuleError(f"{source_file}: group_by must be host, username, or source_ip")

    min_steps = raw.get("min_steps", len(step_ids))
    if not isinstance(min_steps, int) or min_steps < 2 or min_steps > len(step_ids):
        raise RuleError(
            f"{source_file}: min_steps must be between 2 and the number of steps"
        )

    return CorrelationRule(
        id=rule_id,
        title=str(raw.get("title") or rule_id).strip(),
        level=_level_of(raw, source_file),
        steps=tuple(step_ids),
        group_by=group_by,
        window_seconds=window,
        min_steps=min_steps,
        tags=tuple(str(tag) for tag in _as_list(raw.get("tags") or [])),
        description=str(raw.get("description") or "").strip(),
        falsepositives=tuple(str(item) for item in _as_list(raw.get("falsepositives") or [])),
        source_file=source_file,
    )


def load_rules(directory: Path | None = None) -> tuple[list[Rule], list[CorrelationRule]]:
    """Load every rule file, refusing to start on a broken one.

    A rule that cannot be parsed is an error rather than a warning: a detection
    that silently does not load is worse than one that fails loudly.
    """

    root = directory or RULE_DIR
    if not root.is_dir():
        raise RuleError(f"Rule directory not found: {root}")

    detections: list[Rule] = []
    correlations: list[CorrelationRule] = []
    seen: dict[str, str] = {}

    for path in sorted(root.iterdir()):
        if path.suffix.lower() not in {".yml", ".yaml", ".json"}:
            continue
        raw = _load_mapping(path)
        items = raw.get("rules") if isinstance(raw.get("rules"), list) else [raw]
        for item in items:
            if not isinstance(item, dict):
                raise RuleError(f"{path.name}: every entry under 'rules' must be a mapping")
            # A rule with steps is a correlation rule whether or not the author
            # remembered to say so. Getting this wrong would quietly turn a
            # sequence rule into one that never fires.
            declared = str(item.get("type") or "").strip().lower()
            if not declared and item.get("steps"):
                declared = "correlation"
            kind = declared or "detection"
            if kind == "correlation":
                correlation = _build_correlation(item, path.name)
                identifier = correlation.id
            elif kind == "detection":
                detection = _build_rule(item, path.name)
                identifier = detection.id
                detections.append(detection)
            else:
                raise RuleError(f"{path.name}: unsupported rule type {kind!r}")
            if identifier in seen:
                raise RuleError(
                    f"Duplicate rule id {identifier!r} in {path.name} and {seen[identifier]}"
                )
            seen[identifier] = path.name
            if kind == "correlation":
                correlations.append(correlation)

    if not detections:
        raise RuleError(f"No detection rules found in {root}")
    return detections, correlations


@dataclass
class RuleMatch:
    """The outcome of evaluating every rule against one event."""

    rule_id: str
    title: str
    severity: str
    techniques: tuple[str, ...]
    matched_on: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.title,
            "severity": self.severity,
            "techniques": list(self.techniques),
            "matched_on": list(self.matched_on),
        }


_SEVERITY_RANK = {level: index for index, level in enumerate(reversed(VALID_LEVELS))}


class RuleEngine:
    """Evaluate loaded detection rules against events."""

    def __init__(
        self,
        rules: Iterable[Rule],
        correlations: Iterable[CorrelationRule] = (),
    ) -> None:
        self.rules: list[Rule] = list(rules)
        self.correlations: list[CorrelationRule] = list(correlations)
        if not self.rules:
            raise RuleError("A rule engine needs at least one rule")

    @classmethod
    def from_directory(cls, directory: Path | None = None) -> "RuleEngine":
        detections, correlations = load_rules(directory)
        return cls(detections, correlations)

    def by_id(self, rule_id: str) -> Rule | None:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def match(self, payload: dict[str, Any]) -> RuleMatch | None:
        """Return the highest-severity match for one event, or None.

        Severity decides the winner when several rules match, so a High rule is
        never masked by a Low one that happened to be evaluated first.
        """

        fields = event_fields(payload)
        matches: list[RuleMatch] = []
        for rule in self.rules:
            if rule_matches(fields, rule):
                matches.append(
                    RuleMatch(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.level,
                        techniques=rule.techniques,
                        matched_on=tuple(matched_conditions(fields, rule)),
                    )
                )

        if not matches:
            return None

        matches.sort(key=lambda item: _SEVERITY_RANK.get(item.severity, 0), reverse=True)
        return matches[0]

    def coverage(self) -> list[dict[str, Any]]:
        """Every detection rule, with the ATT&CK techniques it covers."""

        return [
            {
                "rule_id": rule.id,
                "title": rule.title,
                "level": rule.level,
                "techniques": list(rule.techniques),
                "tags": list(rule.tags),
                "logsource": rule.logsource,
                "source_file": rule.source_file,
                "description": rule.description,
                "falsepositives": list(rule.falsepositives),
            }
            for rule in sorted(self.rules, key=lambda item: (item.level, item.id))
        ]

    def correlation_coverage(self) -> list[dict[str, Any]]:
        """Every correlation rule, with the steps it watches for."""

        return [
            {
                "rule_id": rule.id,
                "title": rule.title,
                "level": rule.level,
                "steps": list(rule.steps),
                "group_by": rule.group_by,
                "window_seconds": rule.window_seconds,
                "min_steps": rule.min_steps,
                "techniques": list(rule.techniques),
                "tags": list(rule.tags),
                "description": rule.description,
                "source_file": rule.source_file,
            }
            for rule in sorted(self.correlations, key=lambda item: item.id)
        ]

    def attack_coverage(self) -> list[dict[str, Any]]:
        """Technique counts across every detection rule, for the coverage view."""

        counts: dict[str, int] = {}
        for rule in self.rules:
            for technique in rule.techniques:
                counts[technique] = counts.get(technique, 0) + 1
        return [
            {"technique": technique, "rules": count}
            for technique, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        ]


_shared_lock = threading.Lock()
_shared_engine: "RuleEngine | None" = None


def shared_engine() -> "RuleEngine":
    """The process-wide engine for the rules shipped with this project.

    Loaded once and reused: reading a directory of rule files on every event
    would be the slowest part of ingestion.
    """

    global _shared_engine
    with _shared_lock:
        if _shared_engine is None:
            _shared_engine = RuleEngine.from_directory()
        return _shared_engine
