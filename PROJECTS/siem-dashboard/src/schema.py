"""Canonical event schema and per-source normalisation for the SIEM.

Each collector in this project produces events in a different shape. The Windows
collector emits a payload with a ``channel``/``event_id`` pair plus a flat
``fields`` mapping of EventData; ``pcap_ingest`` emits one event per network flow
(or per DNS question); the HTTP API accepts whatever flat JSON an operator posts.
This module defines the single record the rest of the pipeline can rely on, and
the mapping from each producer shape onto it.

The canonical record
--------------------

``normalise_event`` returns a plain ``dict`` with exactly the keys below, so a
consumer never has to test for a missing key. A field the source does not supply
is ``None`` (or the documented default). The producers use the placeholder
strings ``"unknown"`` and ``"localhost"`` to mean "not known"; those are
normalised to ``None`` here so a consumer can tell a known value from an absent
one. ``"local"`` is kept, because the Windows collector uses it deliberately for
a loopback address rather than for an absent one.

================  ==============  =========  ==========================================
field             type            required   meaning
================  ==============  =========  ==========================================
timestamp         string          no         When the event happened, as a UTC
                                             ``YYYY-MM-DD HH:MM:SS`` string (the
                                             format the store already uses).
                                             Defaults to the current UTC time.
host_id           string          no         The host or machine the event is about.
source            string          no         Which normaliser produced this record:
                                             one of ``SUPPORTED_SOURCES``. Defaults
                                             to the auto-detected source.
event_type        string          no         A short category for the event: the
                                             Windows ``channel:event_id``, a Sysmon
                                             operation name such as
                                             ``ProcessCreate``, ``network-flow`` /
                                             ``dns-query`` for a capture, or a
                                             free-form ``type``/``event_id`` for
                                             generic JSON.
severity          string          no         ``High``, ``Medium`` or ``Low``.
                                             Defaults to ``Low``.
message           string          yes        Human-readable description of what
                                             happened. An event with no message is
                                             rejected.
user              string          no         Account the event is attributed to.
process           string          no         Process image or name involved.
command_line      string          no         Full command line of ``process``.
src_ip            string          no         Source network address.
dst_ip            string          no         Destination network address.
dst_port          integer         no         Destination port, 0-65535.
dns_query         string          no         DNS name that was queried.
file_hash         string          no         A file hash; a SHA256 is preferred
                                             when a source offers several.
rule_id           string          no         Identifier of the detection rule
                                             that flagged this event, if any.
techniques        array<string>   no         ATT&CK technique identifiers, e.g.
                                             ``["T1059.001"]``. Defaults to ``[]``.
raw               object          no         The original input record, unchanged.
                                             Unknown fields survive here.
================  ==============  =========  ==========================================

Required and optional
---------------------

Only ``message`` is required: an event that says nothing is not an event. Every
other field is optional. ``timestamp`` is optional because the pipeline stamps a
record with the current UTC time when the source has none, and ``source`` is
optional because it is auto-detected. ``raw`` always carries the original dict,
so nothing a source sent is lost even when the canonical record cannot represent
it.

Per-source mapping
------------------

``windows-event-log``
    Input is the payload ``windows_collector.windows_event_to_payload`` produces,
    or a raw Windows event record (the ``Id``/``Provider``/``Xml`` shape the
    collector reads). A raw record is converted through that same function first,
    so the username/IP extraction and severity classification are identical to
    the collector's. ``channel``/``event_id`` become ``event_type``;
    ``username``/``host``/``source_ip`` become ``user``/``host_id``/``src_ip``;
    EventData supplies ``process``/``command_line``.

``sysmon``
    The same Windows shape, but the channel is
    ``Microsoft-Windows-Sysmon/Operational``. The Sysmon EventData keys are read
    directly: ``Image`` -> ``process``, ``CommandLine`` -> ``command_line``,
    ``User`` -> ``user``, ``SourceIp``/``DestinationIp``/``DestinationPort`` ->
    ``src_ip``/``dst_ip``/``dst_port``, ``QueryName`` -> ``dns_query``, and the
    ``Hashes`` string -> ``file_hash``. ``event_type`` is the Sysmon operation
    name for the event id (``SYSMON_EVENT_TYPES``). Detection is by channel name,
    so a collector payload whose ``source`` says ``windows-event-log`` is still
    mapped as Sysmon.

``pcap-flow``
    Input is what ``pcap_ingest.flow_payloads`` produces. Its ``fields`` mapping
    supplies ``source_address``/``destination_address``/``destination_port`` (a
    flow) or ``query_name`` (a DNS question). ``event_type`` is ``network-flow``
    or ``dns-query``.

``generic-json``
    Arbitrary flat key/value events, including the payload shape
    ``app.normalise_payload`` already accepts. Aliases are resolved the way that
    function resolves them: ``message`` or ``event``; ``severity`` or ``level``;
    ``user`` or ``username``; ``host_id``/``host``/``hostname``; ``src_ip`` or
    ``source_ip`` or ``ip``; ``event_type`` or ``type`` or ``event_id`` or ``id``.

``to_payload`` maps a canonical record back onto the flat dict that
``app.normalise_payload`` accepts, which is how this module stays compatible
with the events the application already ingests.

Nothing here opens a database or reads a rule file: the mapping is pure and
takes only the input record.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable

from .windows_collector import severity_from_windows_level, windows_event_to_payload

# The canonical field order, as documented above. ``normalise_event`` always
# returns exactly these keys.
CANONICAL_FIELDS: tuple[str, ...] = (
    "timestamp",
    "host_id",
    "source",
    "event_type",
    "severity",
    "message",
    "user",
    "process",
    "command_line",
    "src_ip",
    "dst_ip",
    "dst_port",
    "dns_query",
    "file_hash",
    "rule_id",
    "techniques",
    "raw",
)

# Fields a record cannot omit. Everything else has a documented default.
REQUIRED_FIELDS: tuple[str, ...] = ("message",)

# The sources this module can normalise. The name is also the value written to
# the canonical ``source`` field.
SUPPORTED_SOURCES: tuple[str, ...] = (
    "windows-event-log",
    "sysmon",
    "pcap-flow",
    "generic-json",
)

VALID_SEVERITIES: tuple[str, ...] = ("High", "Medium", "Low")

# Severity words the sources use that are not themselves a canonical level.
# Windows event levels are handled by ``severity_from_windows_level`` semantics;
# these are the rest.
SEVERITY_SYNONYMS: dict[str, str] = {
    "critical": "High",
    "severe": "High",
    "error": "High",
    "fatal": "High",
    "warning": "Medium",
    "warn": "Medium",
    "moderate": "Medium",
    "information": "Low",
    "informational": "Low",
    "info": "Low",
    "debug": "Low",
    "verbose": "Low",
    "trace": "Low",
    "notice": "Low",
}

# Sysmon event ids to operation names, so ``event_type`` says what happened
# rather than only a number. Taken from the Sysmon documentation.
SYSMON_EVENT_TYPES: dict[str, str] = {
    "1": "ProcessCreate",
    "2": "FileCreateTime",
    "3": "NetworkConnect",
    "4": "SysmonServiceStateChange",
    "5": "ProcessTerminate",
    "6": "DriverLoad",
    "7": "ImageLoad",
    "8": "CreateRemoteThread",
    "9": "RawAccessRead",
    "10": "ProcessAccess",
    "11": "FileCreate",
    "12": "RegistryEventObjectCreateDelete",
    "13": "RegistryEventValueSet",
    "14": "RegistryEventKeyRename",
    "15": "FileCreateStreamHash",
    "16": "ServiceConfigurationChange",
    "17": "PipeEventCreate",
    "18": "PipeEventConnect",
    "19": "WmiEventFilter",
    "20": "WmiEventConsumer",
    "21": "WmiEventConsumerToFilter",
    "22": "DnsQuery",
    "23": "FileDelete",
    "24": "ClipboardChange",
    "25": "ProcessTampering",
    "26": "FileDeleteDetected",
    "27": "FileBlockExecutable",
    "28": "FileBlockShredding",
    "29": "FileExecutableDetected",
}

# Short names a caller might use for a source, mapped to the canonical one.
SOURCE_ALIASES: dict[str, str] = {
    "windows": "windows-event-log",
    "event-log": "windows-event-log",
    "eventlog": "windows-event-log",
    "winlog": "windows-event-log",
    "pcap": "pcap-flow",
    "network": "pcap-flow",
    "flow": "pcap-flow",
    "netflow": "pcap-flow",
    "json": "generic-json",
    "generic": "generic-json",
}

# Placeholder strings the producers use for "not known".
_PLACEHOLDERS: tuple[str, ...] = ("unknown",)

# Optional text fields that are cleaned to ``None`` when blank or a placeholder.
_TEXT_FIELDS: tuple[str, ...] = (
    "source",
    "event_type",
    "user",
    "process",
    "command_line",
    "src_ip",
    "dst_ip",
    "dns_query",
    "file_hash",
    "rule_id",
)

_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


def coerce_timestamp(value: Any) -> str:
    """Return a UTC timestamp in the format the event store already uses.

    Handles every shape the existing pipeline accepts: an ISO-8601 string with
    or without a ``Z`` or numeric offset, a space-separated date and time, and
    ``None`` or an empty string, which becomes the current UTC time. As an
    extension it also accepts a POSIX epoch number. Anything else raises
    ``ValueError``, naming the value.
    """

    if value is None or not str(value).strip():
        return datetime.now(timezone.utc).strftime(_TIMESTAMP_FORMAT)

    if isinstance(value, bool):  # bool is an int subclass; it is never a date.
        raise ValueError(f"Invalid timestamp: {value!r}")

    if isinstance(value, (int, float)):
        try:
            stamp = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError(f"Invalid timestamp: {value!r}") from exc
        return stamp.strftime(_TIMESTAMP_FORMAT)

    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid timestamp: {text}") from exc

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed.strftime(_TIMESTAMP_FORMAT)


def normalise_severity(value: Any) -> str:
    """Return a supported severity, matching ``app.normalise_severity``."""

    candidate = (str(value) if value is not None else "Low").strip().title()
    if candidate not in VALID_SEVERITIES:
        raise ValueError(
            f"Unsupported severity {value!r}. Expected High, Medium, or Low."
        )
    return candidate


def _text(value: Any) -> str | None:
    """Return a stripped string, or ``None`` when there is nothing to return."""

    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _clean(value: Any, placeholders: tuple[str, ...] = _PLACEHOLDERS) -> str | None:
    """A stripped string, or ``None`` when blank or a producer placeholder."""

    text = _text(value)
    if text is None:
        return None
    if text.lower() in placeholders:
        return None
    return text


def _coerce_severity(value: Any, level: Any = None) -> str:
    """Map a severity or a level word onto a canonical severity.

    A value that is already ``High``/``Medium``/``Low`` is kept. A known synonym
    (``critical``, ``warning``, ``information`` ...) is mapped. Otherwise the
    level is tried, and a genuinely unknown word raises, as
    ``app.normalise_severity`` does.
    """

    text = _text(value)
    if text is None:
        text = _text(level)
    if text is None:
        return "Low"
    lowered = text.lower()
    if lowered in SEVERITY_SYNONYMS:
        return SEVERITY_SYNONYMS[lowered]
    return normalise_severity(text)


def _coerce_techniques(value: Any) -> list[str]:
    """Return a list of technique identifiers from a list or a comma string."""

    if value in (None, "", [], {}):
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [str(item).strip() for item in value]
    elif isinstance(value, str):
        items = [part.strip() for part in value.split(",")]
    else:
        items = [str(value).strip()]
    return [item for item in items if item]


def _coerce_port(value: Any) -> int | None:
    """Return a port number, or ``None`` when none was given."""

    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid dst_port: {value!r}") from exc
    if not 0 <= port <= 65535:
        raise ValueError(f"Invalid dst_port: {value!r}")
    return port


def _hash_from(value: Any) -> str | None:
    """Return one hash from a Sysmon ``Hashes`` string, preferring SHA256."""

    text = _text(value)
    if text is None:
        return None
    digests: dict[str, str] = {}
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            algorithm, _, digest = part.partition("=")
            digests[algorithm.strip().upper()] = digest.strip()
        else:
            digests.setdefault("", part)
    for algorithm in ("SHA256", "SHA1", "MD5", "IMPHASH"):
        if digests.get(algorithm):
            return digests[algorithm]
    for digest in digests.values():
        if digest:
            return digest
    return None


def _event_data(payload: dict[str, Any]) -> dict[str, str]:
    """The structured EventData a collector payload carries.

    The collector puts it in ``fields`` and also serialises it into ``raw_log``.
    Either is read, so a payload that kept only one of them still maps.
    """

    data = payload.get("fields")
    if isinstance(data, dict):
        return {str(key): value for key, value in data.items()}

    raw_log = payload.get("raw_log")
    if isinstance(raw_log, str) and raw_log.strip():
        try:
            parsed = json.loads(raw_log)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            nested = parsed.get("EventData")
            if isinstance(nested, dict):
                return {str(key): value for key, value in nested.items()}
    return {}


def _as_windows_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """Return a collector payload, converting a raw Windows record if needed."""

    if "event_id" not in raw and ("Id" in raw or "Xml" in raw):
        channel = _text(raw.get("channel") or raw.get("LogName")) or "unknown"
        return windows_event_to_payload(channel, raw)
    return raw


def _event_type_for(channel: str | None, event_id: str | None) -> str | None:
    """A Windows event type of ``channel:event_id``, or the part we have."""

    channel = _text(channel)
    if event_id and channel and channel.lower() != "unknown":
        return f"{channel}:{event_id}"
    return event_id or channel


def _finalise(raw: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    """Fill a partial mapping into the canonical record and validate it."""

    record: dict[str, Any] = {name: None for name in CANONICAL_FIELDS}
    for name in CANONICAL_FIELDS:
        if name in event and event[name] is not None:
            record[name] = event[name]

    record["raw"] = dict(raw)
    record["timestamp"] = coerce_timestamp(event.get("timestamp"))
    record["severity"] = _coerce_severity(event.get("severity")) or "Low"
    record["techniques"] = _coerce_techniques(event.get("techniques"))
    record["dst_port"] = _coerce_port(event.get("dst_port"))

    message = event.get("message")
    if message is None or not str(message).strip():
        raise ValueError("Event is missing a required field: 'message'")
    record["message"] = str(message).strip()

    for name in _TEXT_FIELDS:
        record[name] = _clean(record.get(name))
    record["host_id"] = _clean(record.get("host_id"), ("unknown", "localhost"))

    return record


def from_windows_event_log(raw: dict[str, Any]) -> dict[str, Any]:
    """Map a Windows Event Log record onto the canonical schema."""

    payload = _as_windows_payload(raw)
    data = _event_data(payload)

    channel = _text(payload.get("channel") or payload.get("LogName") or raw.get("LogName")) or "unknown"
    event_id = _text(payload.get("event_id") or payload.get("Id"))
    provider = _text(payload.get("provider") or payload.get("Provider")) or "unknown"
    message = payload.get("message") or f"{provider} event {event_id or 'unknown'}"

    event = {
        "timestamp": payload.get("timestamp") or payload.get("TimeCreated") or raw.get("TimeCreated"),
        "host_id": payload.get("host") or payload.get("Machine") or raw.get("Machine"),
        "source": "windows-event-log",
        "event_type": _event_type_for(channel, event_id),
        "severity": _coerce_severity(payload.get("severity"), payload.get("level") or payload.get("Level")),
        "message": message,
        "user": payload.get("username")
        or data.get("TargetUserName")
        or data.get("SubjectUserName")
        or data.get("AccountName"),
        "process": data.get("ProcessName") or data.get("Image"),
        "command_line": data.get("CommandLine") or data.get("ProcessCommandLine"),
        "src_ip": payload.get("source_ip")
        or data.get("IpAddress")
        or data.get("SourceNetworkAddress"),
        "dst_ip": data.get("DestinationIp"),
        "dst_port": data.get("DestinationPort"),
        "dns_query": data.get("QueryName"),
        "file_hash": _hash_from(data.get("Hashes")),
        "rule_id": payload.get("rule_id"),
        "techniques": payload.get("techniques"),
    }
    return _finalise(raw, event)


def from_sysmon(raw: dict[str, Any]) -> dict[str, Any]:
    """Map a Sysmon event (collector payload or raw record) onto the schema."""

    payload = _as_windows_payload(raw)
    data = _event_data(payload)

    event_id = _text(payload.get("event_id") or payload.get("Id")) or ""
    if event_id in SYSMON_EVENT_TYPES:
        event_type = SYSMON_EVENT_TYPES[event_id]
    elif event_id:
        event_type = f"sysmon:{event_id}"
    else:
        event_type = "sysmon"
    message = payload.get("message") or data.get("Description") or f"Sysmon {event_type}"

    event = {
        "timestamp": payload.get("timestamp")
        or payload.get("TimeCreated")
        or data.get("UtcTime"),
        "host_id": payload.get("host") or data.get("Computer") or payload.get("Machine"),
        "source": "sysmon",
        "event_type": event_type,
        "severity": _coerce_severity(payload.get("severity"), payload.get("level")),
        "message": message,
        "user": data.get("User") or payload.get("username"),
        "process": data.get("Image") or data.get("ProcessImage"),
        "command_line": data.get("CommandLine"),
        "src_ip": data.get("SourceIp") or data.get("SourceAddress") or payload.get("source_ip"),
        "dst_ip": data.get("DestinationIp") or data.get("DestinationHostname"),
        "dst_port": data.get("DestinationPort"),
        "dns_query": data.get("QueryName"),
        "file_hash": _hash_from(data.get("Hashes")),
        "rule_id": payload.get("rule_id"),
        "techniques": payload.get("techniques"),
    }
    return _finalise(raw, event)


def from_pcap_flow(raw: dict[str, Any]) -> dict[str, Any]:
    """Map a ``pcap_ingest`` flow or DNS payload onto the canonical schema."""

    fields = raw.get("fields") if isinstance(raw.get("fields"), dict) else {}
    kind = (_text(raw.get("event_id")) or "").upper()

    event = {
        "timestamp": raw.get("timestamp") or fields.get("first_seen"),
        "host_id": raw.get("host"),
        "source": "pcap-flow",
        "event_type": "dns-query" if kind == "DNS" else "network-flow",
        "severity": _coerce_severity(raw.get("severity"), raw.get("level")),
        "message": raw.get("message"),
        "user": raw.get("username"),
        "process": None,
        "command_line": None,
        "src_ip": fields.get("source_address") or raw.get("source_address") or raw.get("source_ip"),
        "dst_ip": fields.get("destination_address") or raw.get("destination_address"),
        "dst_port": fields.get("destination_port") or raw.get("destination_port"),
        "dns_query": fields.get("query_name") or raw.get("query_name"),
        "file_hash": None,
        "rule_id": raw.get("rule_id"),
        "techniques": raw.get("techniques"),
    }
    return _finalise(raw, event)


def from_generic_json(raw: dict[str, Any]) -> dict[str, Any]:
    """Map an arbitrary flat key/value event onto the canonical schema."""

    event = {
        "timestamp": raw.get("timestamp")
        or raw.get("time")
        or raw.get("@timestamp")
        or raw.get("date")
        or raw.get("datetime"),
        "host_id": raw.get("host_id")
        or raw.get("host")
        or raw.get("hostname")
        or raw.get("machine")
        or raw.get("computer"),
        "source": "generic-json",
        "event_type": raw.get("event_type")
        or raw.get("type")
        or raw.get("event_id")
        or raw.get("id"),
        "severity": _coerce_severity(raw.get("severity"), raw.get("level")),
        "message": raw.get("message") or raw.get("event") or raw.get("msg") or raw.get("description"),
        "user": raw.get("user") or raw.get("username") or raw.get("account"),
        "process": raw.get("process") or raw.get("image") or raw.get("process_name"),
        "command_line": raw.get("command_line")
        or raw.get("cmd")
        or raw.get("command")
        or raw.get("process_command_line"),
        "src_ip": raw.get("src_ip") or raw.get("source_ip") or raw.get("src") or raw.get("ip"),
        "dst_ip": raw.get("dst_ip")
        or raw.get("destination_ip")
        or raw.get("dest_ip")
        or raw.get("dst"),
        "dst_port": raw.get("dst_port")
        or raw.get("destination_port")
        or raw.get("dest_port")
        or raw.get("dport"),
        "dns_query": raw.get("dns_query") or raw.get("query") or raw.get("query_name"),
        "file_hash": raw.get("file_hash")
        or raw.get("hash")
        or raw.get("sha256")
        or raw.get("md5")
        or raw.get("sha1"),
        "rule_id": raw.get("rule_id"),
        "techniques": raw.get("techniques")
        or raw.get("mitre")
        or raw.get("attack")
        or raw.get("technique"),
    }
    return _finalise(raw, event)


# The mapper for each supported source.
SOURCE_MAPPERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "windows-event-log": from_windows_event_log,
    "sysmon": from_sysmon,
    "pcap-flow": from_pcap_flow,
    "generic-json": from_generic_json,
}


def detect_source(raw: dict[str, Any]) -> str:
    """Return the supported source that best matches an input record.

    The Sysmon channel is checked before the declared ``source``, because the
    Windows collector labels a Sysmon payload ``windows-event-log`` while the
    channel says otherwise.
    """

    if not isinstance(raw, dict):
        raise ValueError("Each event must be a JSON object")

    channel = _text(raw.get("channel") or raw.get("LogName") or raw.get("log_name")) or ""
    provider = _text(raw.get("provider") or raw.get("Provider")) or ""
    declared = (_text(raw.get("source")) or "").lower()

    if "sysmon" in channel.lower() or "sysmon" in provider.lower() or declared == "sysmon":
        return "sysmon"
    if declared in SOURCE_MAPPERS:
        return declared
    if declared in SOURCE_ALIASES:
        return SOURCE_ALIASES[declared]
    if raw.get("Xml") or ("Id" in raw and "Provider" in raw):
        return "windows-event-log"
    if channel.lower() == "network" or any(
        key in raw for key in ("destination_port", "source_address", "destination_address")
    ):
        return "pcap-flow"
    return "generic-json"


def normalise_event(raw: dict[str, Any], source: str | None = None) -> dict[str, Any]:
    """Map one input record onto the canonical schema.

    ``source`` names the mapper to use. When it is ``None`` the source is
    detected from the record with ``detect_source``. A missing required field,
    an unknown source, or an invalid value in a known field raises ``ValueError``.
    """

    if not isinstance(raw, dict):
        raise ValueError("Each event must be a JSON object")

    if source is None:
        resolved = detect_source(raw)
    else:
        if not isinstance(source, str) or not source.strip():
            raise ValueError("source must be a non-empty string")
        resolved = source.strip().lower()
        resolved = SOURCE_ALIASES.get(resolved, resolved)

    mapper = SOURCE_MAPPERS.get(resolved)
    if mapper is None:
        raise ValueError(
            f"Unknown source {resolved!r}. Expected one of: {', '.join(SUPPORTED_SOURCES)}."
        )
    return mapper(raw)


def to_payload(event: dict[str, Any], source_default: str = "api") -> dict[str, Any]:
    """Convert a canonical record back into the flat payload the app accepts.

    This is the compatibility bridge: the result can be handed to
    ``app.normalise_payload`` unchanged. The producer's own ``source`` label is
    restored from ``raw`` when it is present, so the stored value does not change.
    """

    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    source = _text(raw.get("source")) or _text(event.get("source")) or source_default
    techniques = event.get("techniques") or []

    payload: dict[str, Any] = {key: value for key, value in raw.items() if key != "is_alert"}
    if isinstance(raw.get("is_alert"), bool):
        payload["is_alert"] = raw["is_alert"]
    payload.update(
        {
            "timestamp": event.get("timestamp"),
            "message": event.get("message") or "",
            "severity": event.get("severity") or "Low",
            "source": source,
            "channel": raw.get("channel") or event.get("event_type") or source,
            "provider": raw.get("provider") or "unknown",
            "event_id": raw.get("event_id") or raw.get("id") or "unknown",
            "level": raw.get("level") or "Information",
            "username": event.get("user") or raw.get("username") or "unknown",
            "host": event.get("host_id") or "unknown",
            "source_ip": event.get("src_ip") or "local",
            "rule_id": event.get("rule_id") or "",
            "techniques": ",".join(str(item) for item in techniques),
        }
    )
    return payload


def describe_schema() -> dict[str, Any]:
    """Describe the canonical record so the dashboard can document itself."""

    fields = [
        {
            "name": "timestamp",
            "type": "string",
            "required": False,
            "description": "UTC time of the event as 'YYYY-MM-DD HH:MM:SS'; defaults to now.",
        },
        {
            "name": "host_id",
            "type": "string",
            "required": False,
            "description": "Host or machine the event is about.",
        },
        {
            "name": "source",
            "type": "string",
            "required": False,
            "description": "Normaliser that produced the record; one of the supported sources.",
        },
        {
            "name": "event_type",
            "type": "string",
            "required": False,
            "description": "Short category: channel:event_id, a Sysmon operation, network-flow/dns-query, or a free-form type.",
        },
        {
            "name": "severity",
            "type": "string",
            "required": False,
            "description": "High, Medium or Low; defaults to Low.",
        },
        {
            "name": "message",
            "type": "string",
            "required": True,
            "description": "Human-readable description of what happened.",
        },
        {
            "name": "user",
            "type": "string",
            "required": False,
            "description": "Account the event is attributed to.",
        },
        {
            "name": "process",
            "type": "string",
            "required": False,
            "description": "Process image or name involved.",
        },
        {
            "name": "command_line",
            "type": "string",
            "required": False,
            "description": "Full command line of the process.",
        },
        {
            "name": "src_ip",
            "type": "string",
            "required": False,
            "description": "Source network address.",
        },
        {
            "name": "dst_ip",
            "type": "string",
            "required": False,
            "description": "Destination network address.",
        },
        {
            "name": "dst_port",
            "type": "integer",
            "required": False,
            "description": "Destination port, 0-65535.",
        },
        {
            "name": "dns_query",
            "type": "string",
            "required": False,
            "description": "DNS name that was queried.",
        },
        {
            "name": "file_hash",
            "type": "string",
            "required": False,
            "description": "A file hash, preferring SHA256 when several are offered.",
        },
        {
            "name": "rule_id",
            "type": "string",
            "required": False,
            "description": "Detection rule that flagged the event, if any.",
        },
        {
            "name": "techniques",
            "type": "array<string>",
            "required": False,
            "description": "ATT&CK technique identifiers; defaults to an empty list.",
        },
        {
            "name": "raw",
            "type": "object",
            "required": False,
            "description": "The original input record, unchanged.",
        },
    ]

    return {
        "fields": fields,
        "required": list(REQUIRED_FIELDS),
        "sources": list(SUPPORTED_SOURCES),
        "notes": (
            "Optional fields are None when the source does not supply them. The "
            "producer placeholders 'unknown' and 'localhost' are normalised to "
            "None; 'local' is kept. Unknown input fields survive in 'raw'."
        ),
    }
