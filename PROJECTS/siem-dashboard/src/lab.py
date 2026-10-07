"""The labelled corpus: real attack techniques, captured with real telemetry.

Everywhere else in this project, a detection rule is judged by whether it looks
sensible. This module is what makes it judged by a number instead.

The techniques are Atomic Red Team's, taken from the project's own YAML and
narrowed to an allowlist in this file. That narrowing is the important part: the
T1082 atomics include several "WinPwn" tests that download and execute
PowerShell from a URL, and those must never run on a machine anybody cares
about. Nothing outside `ALLOWED_TECHNIQUES` can be executed by this module --
not by a flag, not by an argument -- because the command text lives in this file
rather than being read from the atomics tree at run time. The tree is the source
of the text; this file is the decision about it.

Ground truth comes from the run, not from the telemetry. A window is labelled
with the technique that was executed during it, so a rule that fires in that
window can be scored against something known to be true rather than against a
guess about the event. A benign window is labelled the same way -- nothing was
executed in it -- which is what makes a false positive measurable at all.

The capture needs an elevated shell, because the Sysmon channel is not readable
without one. `python -m src.lab capture` says so rather than failing obscurely.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .windows_collector import CHANNELS, SYSMON_CHANNEL, windows_event_to_payload

__all__ = [
    "Technique",
    "ALLOWED_TECHNIQUES",
    "BENIGN",
    "CaptureError",
    "read_since",
    "read_all",
    "run_technique",
    "capture_corpus",
]

# A technique whose effect is to read something and print it. Every command here
# was read out of the atomics tree, checked for network access, for anything that
# writes to the machine, and for anything needing elevation, and only then
# copied in. The `atomic` field names the test it came from so the provenance is
# checkable rather than asserted.
@dataclass(frozen=True)
class Technique:
    attack_id: str
    name: str
    atomic: str
    executor: str
    command: str
    arguments: dict[str, str] = field(default_factory=dict)

    def resolved(self) -> str:
        """The command with Atomic's input arguments substituted."""
        text = self.command
        for key, value in self.arguments.items():
            text = text.replace("#{%s}" % key, value)
        return text

    def as_dict(self) -> dict:
        return {
            "attack_id": self.attack_id,
            "name": self.name,
            "atomic": self.atomic,
            "executor": self.executor,
            "command": self.command,
            "arguments": self.arguments,
            "resolved": self.resolved(),
        }


ALLOWED_TECHNIQUES: tuple[Technique, ...] = (
    Technique(
        "T1082", "System Information Discovery",
        "System Information Discovery", "command_prompt",
        "systeminfo ; reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
    ),
    Technique(
        "T1082", "Environment variables discovery",
        "Environment variables discovery on windows", "command_prompt",
        "set",
    ),
    Technique(
        "T1082", "Machine GUID discovery",
        "Windows MachineGUID Discovery", "command_prompt",
        "REG QUERY HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid",
    ),
    Technique(
        "T1082", "OS product name discovery",
        "Discover OS Product Name via Registry", "command_prompt",
        "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v ProductName",
    ),
    Technique(
        "T1057", "Process discovery with tasklist",
        "Process Discovery - tasklist", "command_prompt",
        "tasklist",
    ),
    Technique(
        "T1057", "Process discovery with Get-Process",
        "Process Discovery - Get-Process", "powershell",
        "Get-Process | Select-Object -First 5 | Out-Null",
    ),
    Technique(
        "T1016", "Network configuration discovery",
        "System Network Configuration Discovery on Windows", "command_prompt",
        "ipconfig /all ; netsh interface show interface ; arp -a ; net config",
    ),
    Technique(
        "T1016", "Firewall rule discovery",
        "List Windows Firewall Rules", "command_prompt",
        "netsh advfirewall firewall show rule name=all",
    ),
    Technique(
        "T1518", "Installed software discovery",
        "Applications Installed", "powershell",
        "Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
        "Select-Object -First 5 DisplayName | Out-Null",
    ),
    Technique(
        "T1033", "Owner and user discovery",
        "User Discovery - whoami", "command_prompt",
        "whoami #{whoami_args}",
        {"whoami_args": "/all"},
    ),
    # The encoded command is Atomic's own default for this test. It decodes to
    # `iex 'Write-Host "Hello, from PowerShell!"'` -- deliberately obfuscated to
    # be a realistic T1059.001 specimen, and benign in effect. It is the one
    # technique here that a rule is written to catch, which is why the corpus
    # would be worth much less without it.
    Technique(
        "T1059.001", "Encoded PowerShell command",
        "PowerShell Command Execution", "command_prompt",
        "powershell.exe -e #{obfuscated_code}",
        {"obfuscated_code":
         "JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIA"
         "KwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwA"
         "IABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwA"
         "bAAhACcAIgApAA=="},
    ),
)

BENIGN = "benign"

# Windows reuses process ids and the event log is not instantaneous, so a window
# is closed a moment after the command returns rather than the instant it does.
SETTLE_SECONDS = 3.0


class CaptureError(RuntimeError):
    """Raised when the capture cannot do its job, with the reason."""


@dataclass(frozen=True)
class Window:
    """One labelled slice of telemetry."""

    label: str                  # an ATT&CK id, or BENIGN
    technique: str              # a human name, or BENIGN
    started: float
    ended: float
    events: tuple[dict, ...]    # SIEM payloads, as windows_event_to_payload returns

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "technique": self.technique,
            "started": self.started,
            "ended": self.ended,
            "events": list(self.events),
        }


# Every PowerShell the harness starts in order to *read* the log is itself in the
# log it is reading, and Sysmon records its creation before the query runs. One
# process is not enough to remember: the first version filtered each read against
# its own pid, and every earlier reader -- the marks query, and the previous
# window's read -- stayed in the corpus. Thirty of the first 313 captured events
# were the harness talking to itself, which is a false positive the measurement
# would have blamed on a rule.
_READER_PIDS: set[int] = set()


def reset_reader_pids() -> None:
    """Forget the readers seen so far. Called at the start of a capture."""
    _READER_PIDS.clear()


def reader_pids() -> set[int]:
    return set(_READER_PIDS)


def _powershell(script: str, timeout: int = 120) -> tuple[str, int]:
    """Run a PowerShell one-shot and return its standard output.

    The stdout is coerced to a string rather than trusted to be one. A killed or
    unusually-terminated child can leave `subprocess` reporting `None` here, and
    the resulting AttributeError reads as a bug in the caller -- which is exactly
    where it was first chased, at the wrong end of the call.
    """
    try:
        process = subprocess.Popen(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    except FileNotFoundError as exc:
        # This half of the project reads the Windows event log, so it needs
        # Windows. Saying so beats a bare OSError from three frames down.
        raise CaptureError(
            "the event log can only be read on Windows: no PowerShell on this host") from exc
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        raise CaptureError("PowerShell did not return within %d seconds" % timeout)
    stdout = stdout if isinstance(stdout, str) else ""
    if process.returncode and not stdout.strip():
        raise CaptureError(((stderr or "").strip() or "PowerShell failed")[:400])
    # The pid goes back with the output because the reader's own process is
    # telemetry too, and the caller has to be able to drop it -- and it is
    # remembered, because a later read will be the one that captures it.
    _READER_PIDS.add(process.pid)
    return stdout, process.pid


def _highest_record_id(channel: str) -> int:
    """The newest record id in a channel, so a window can start after it."""
    script = (
        "$e = Get-WinEvent -LogName '%s' -MaxEvents 1 -ErrorAction SilentlyContinue;"
        "if ($e) { $e.RecordId } else { 0 }" % channel
    )
    text = _powershell(script)[0].strip()
    try:
        return int(text or 0)
    except ValueError:
        return 0


def read_since(channel: str, after_record_id: int, limit: int = 4000) -> list[dict]:
    """Every record newer than `after_record_id`, as SIEM payloads.

    Reading by record id rather than by time is deliberate: a clock that moves,
    or two events in the same millisecond, would make a time window ambiguous,
    and the whole point of a labelled corpus is that the boundary is not.
    """
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$e = Get-WinEvent -LogName '%s' -MaxEvents %d -ErrorAction SilentlyContinue;"
        "if ($e) { $e | ForEach-Object { [pscustomobject]@{"
        " Id=$_.Id; Provider=$_.ProviderName; Level=$_.LevelDisplayName;"
        " RecordId=$_.RecordId; TimeCreated=$_.TimeCreated.ToString('o');"
        " User=$_.UserId; Message=$_.Message; Xml=$_.ToXml() } } | "
        "ConvertTo-Json -Depth 6 -Compress }"
    ) % (channel, limit)
    text = _powershell(script).strip()
    if not text:
        return []
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CaptureError("could not read %s: %s" % (channel, exc)) from exc
    if isinstance(raw, dict):
        raw = [raw]
    payloads = []
    for item in raw:
        try:
            record_id = int(item.get("RecordId") or 0)
        except (TypeError, ValueError):
            record_id = 0
        if record_id <= after_record_id:
            continue
        payload = windows_event_to_payload(channel, item)
        payload["record_id"] = record_id
        payload["captured_channel"] = channel
        payloads.append(payload)
    payloads.sort(key=lambda event: event.get("record_id") or 0)
    return payloads


def read_all(channels, marks: dict[str, int], newest: int = 400,
             runner=None, exclude_pids=None) -> tuple[list[dict], list[str]]:
    """New records across several channels, and the channels that could not be read.

    Returns `(payloads, unreadable)`. The second value is the point of this
    function's shape. A first version read every channel and returned whatever
    came back, which meant that on an unelevated shell -- where Sysmon and
    Security are denied -- it returned a corpus with the two most important
    channels silently missing. The capture would have looked complete and been
    measuring a fraction of the telemetry, which is the worst possible failure
    for something whose entire purpose is to produce a number you can trust.

    So each channel is read inside its own try/catch and a failure is recorded
    rather than swallowed. The caller decides what to do about it; `capture_corpus`
    refuses to write a corpus at all if a channel could not be read.

    The record-id filter is applied here rather than in PowerShell. Passing a
    hashtable lookup into `-FilterXPath` through string concatenation fails with
    exit code 1 and no output on stderr -- a silent failure worth knowing about
    -- and filtering in Python has no such edge.
    """
    if not channels:
        # Nothing to read is not a reason to start a process, and starting one
        # for an empty list is how this failed on a host that has no PowerShell.
        return [], []

    channel_list = ",".join("'%s'" % c for c in channels)
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$all=@(); $bad=@();"
        "foreach ($ch in @(%s)) {"
        "  try {"
        "    $e = Get-WinEvent -LogName $ch -MaxEvents %d -ErrorAction Stop;"
        "    if ($e) { $all += $e | ForEach-Object {"
        "      $x = [xml]$_.ToXml();"
        "      $pairs = @();"
        "      foreach ($d in $x.Event.EventData.Data) {"
        "        $pairs += ('<Data Name=\"' + $d.Name + '\">' + "
        "[System.Security.SecurityElement]::Escape([string]$d.'#text') + '</Data>') };"
        "      $mini = '<Event><System><EventID>' + $_.Id + '</EventID></System>' + "
        "'<EventData>' + ($pairs -join '') + '</EventData></Event>';"
        "      [pscustomobject]@{"
        "        Channel=$ch; Id=$_.Id; Provider=$_.ProviderName; Level=$_.LevelDisplayName;"
        "        RecordId=$_.RecordId; TimeCreated=$_.TimeCreated.ToString('o');"
        "        User=$_.UserId; Xml=$mini;"
        "        Message=$([string]$_.Message).Substring(0, [Math]::Min(1500, ([string]$_.Message).Length))"
        "      } } }"
        "  } catch { $bad += $ch }"
        "};"
        "[pscustomobject]@{ events=@($all); unreadable=@($bad) } | "
        "ConvertTo-Json -Depth 5 -Compress"
    ) % (channel_list, newest)
    text, reader_pid = (runner or _powershell)(script, timeout=300)
    text = text.strip()
    if not text:
        raise CaptureError("the event log read returned nothing at all")
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CaptureError("could not read the event log: %s" % exc) from exc

    raw = envelope.get("events") or []
    if isinstance(raw, dict):
        raw = [raw]
    unreadable = envelope.get("unreadable") or []
    if isinstance(unreadable, str):
        unreadable = [unreadable]

    payloads = []
    self_events = 0
    for item in raw:
        channel = str(item.get("Channel") or "")
        try:
            record_id = int(item.get("RecordId") or 0)
        except (TypeError, ValueError):
            record_id = 0
        if record_id <= marks.get(channel, 0):
            continue                      # older than the window's start
        # Drop the reading process's own footprint. Reading the log means
        # starting a process, and that process is in the log it is reading --
        # Sysmon records its creation before Get-WinEvent ever runs. Left in,
        # every technique window would contain the apparatus used to measure it,
        # and a rule firing on it would be scored as a false positive that the
        # harness caused. The SIEM's own collector guards against the same thing
        # with its own-pid memory; this is the equivalent.
        fields = _event_fields(item)
        exclude = _READER_PIDS if exclude_pids is None else set(exclude_pids) | {reader_pid}
        if _is_reader_own(fields, exclude):
            self_events += 1
            continue
        payload = windows_event_to_payload(channel, item)
        payload["record_id"] = record_id
        payload["captured_channel"] = channel
        payloads.append(payload)
    payloads.sort(key=lambda event: event.get("record_id") or 0)
    return payloads, list(unreadable)

# Sysmon names the process an event is about in the body rather than in the
# record header, so "did we cause this" has to look at the structured fields.
_OWN_PROCESS_FIELDS = ("ProcessId", "SourceProcessId", "ParentProcessId")


def _event_fields(item: dict) -> dict:
    """The EventData of one record, as strings, without going through the schema."""
    import re as _re
    pairs = _re.findall(r'<Data Name="([^"]*)">(.*?)</Data>',
                        str(item.get("Xml") or ""), _re.S)
    return {name: value for name, value in pairs}


def _is_reader_own(fields: dict, reader_pids) -> bool:
    """True when an event describes a process the harness started to read the log.

    Takes a collection rather than a single pid: the reader that captured this
    event is rarely the reader that produced it.
    """
    needles = {str(pid) for pid in reader_pids}
    if not needles:
        return False
    for key in _OWN_PROCESS_FIELDS:
        value = str(fields.get(key) or "").strip()
        if value and value in needles:
            return True
    return False


def _run(command: str, executor: str, attempts: int = 5) -> tuple[int, str]:
    """Run one technique's command, retrying a refused spawn.

    Spawning the child from an elevated parent fails intermittently on this host
    with `PermissionError: WinError 5`, and not deterministically -- one capture
    ran all eleven techniques and the next failed at the third. The commands are
    ordinary read-only recon (`reg query`, `whoami /all`, `systeminfo`), which is
    exactly the shape endpoint protection watches for, so a throttle that clears
    on its own is the likeliest cause and a short backoff is the proportionate
    answer. A refusal that survives five attempts is reported rather than
    swallowed.

    Absolute paths and an explicit working directory remove two other possible
    causes: PATH resolution and a working directory an elevated child may not
    inherit the rights to use.
    """
    system_root = os.environ.get("SystemRoot") or "C:\\Windows"
    if executor == "powershell":
        argv = [os.path.join(system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command]
    else:
        argv = [os.path.join(system_root, "System32", "cmd.exe"), "/C", command]

    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            completed = subprocess.run(argv, capture_output=True, text=True,
                                       timeout=180, cwd=system_root)
            return completed.returncode, (completed.stdout or completed.stderr or "").strip()[:200]
        except PermissionError as exc:          # the intermittent refusal
            last_error = exc
            time.sleep(1.5 * attempt)
        except subprocess.SubprocessError as exc:
            last_error = exc
            time.sleep(1.0)
    raise CaptureError(
        "could not start the command after %d attempts: %s -- %s"
        % (attempts, last_error, command[:80]))

def run_technique(technique: Technique) -> Window:
    """Execute one technique and capture the telemetry window it produced."""
    started = time.time()
    marks = {channel: _highest_record_id(channel) for channel in CHANNELS}
    exit_code, output = _run(technique.resolved(), technique.executor)
    time.sleep(SETTLE_SECONDS)
    ended = time.time()

    events, unreadable = read_all(CHANNELS, marks)
    if unreadable:
        raise CaptureError(
            "these channels could not be read, so this window is incomplete: %s. "
            "The capture needs an elevated shell for Sysmon and Security."
            % ", ".join(unreadable))

    window = Window(label=technique.attack_id,
                    technique="%s (%s)" % (technique.name, technique.atomic),
                    started=started, ended=ended, events=tuple(events))
    return window


# What ordinary activity looks like, so that a benign window contains some.
#
# The first benign windows captured nothing but a sleep, and the result was a
# corpus in which forty-five benign events had no command line between them while
# every technique event had one. A detector asked "is this command unusual for
# this host" cannot answer from data in which the host never ran a command, and
# the anomaly work stalled on that rather than on anything to do with the model.
#
# So a benign window now runs the sort of thing a person runs. Deliberately
# dull, and deliberately including one realistic overlap: `ipconfig` is a
# discovery technique and it is also something somebody types when the wifi
# looks wrong. A baseline that contained no such command would make the
# detection problem look easier than it is.
BENIGN_WORKLOAD: tuple[tuple[str, str], ...] = (
    ("command_prompt", "dir /b C:\\Windows"),
    ("command_prompt", "echo ordinary activity"),
    ("command_prompt", "type C:\\Windows\\win.ini"),
    ("command_prompt", "findstr /i version C:\\Windows\\win.ini"),
    ("command_prompt", "ping -n 1 127.0.0.1"),
    ("powershell", "Get-Date"),
    ("powershell", "Get-ChildItem C:\\Windows -Name | Select-Object -First 5"),
    ("powershell", "Get-Service | Select-Object -First 5"),
    ("command_prompt", "ipconfig"),
)


def capture_benign(seconds: float = 12.0, workload=None, rotation: int = 0) -> Window:
    """A window of ordinary activity.

    This is the half that makes a false positive measurable. A rule that fires
    here fired on the machine going about its business.

    The workload rotates rather than repeating. Running the same nine commands in
    every window made `ipconfig` appear six times, and the network-discovery rule
    was then scored at 0.25 precision for meeting a command that a real person
    types once, not once per hour. The baseline is meant to be ordinary, and
    ordinary activity is not identical every time.
    """
    started = time.time()
    marks = {channel: _highest_record_id(channel) for channel in CHANNELS}
    if workload is None:
        # always the dull core, then a couple of the others by rotation, so the
        # overlap is realistic rather than constant
        core = BENIGN_WORKLOAD[:4]
        extra = BENIGN_WORKLOAD[4:]
        take = 2
        start = (rotation * take) % len(extra)
        workload = core + tuple(extra[(start + i) % len(extra)] for i in range(take))
    # spread over the window rather than fired off at once, so the events land
    # where ordinary activity would land instead of in a single burst
    pause = max(0.0, seconds / max(1, len(workload)))
    for executor, command in workload:
        try:
            _run(command, executor, attempts=2)
        except CaptureError:
            continue                    # an ordinary command failing is ordinary
        time.sleep(pause)
    ended = time.time()

    events, unreadable = read_all(CHANNELS, marks)
    if unreadable:
        raise CaptureError(
            "these channels could not be read, so this window is incomplete: %s. "
            "The capture needs an elevated shell for Sysmon and Security."
            % ", ".join(unreadable))
    return Window(label=BENIGN, technique=BENIGN, started=started, ended=ended,
                  events=tuple(events))


def read_window(channel: str, start: float, end: float, newest: int = 4000,
                runner=None) -> tuple[list[dict], bool]:
    """Everything a channel recorded between two times, and whether it could be read.

    Windows are times rather than record ids because the two have to be taken by
    different processes. Reading Sysmon needs elevation; spawning the techniques
    must *not* have it. Running the encoded-PowerShell atomic from an elevated
    parent is refused outright by endpoint protection -- five attempts in a row --
    and that turned out to be the only thing elevation broke, because the same
    command runs from an ordinary shell. Record-id marks cannot be taken by a
    process that is not there when the technique runs; a pair of timestamps can.

    Returns `(events, readable)`. A channel that could not be read says so rather
    than returning an empty list, for the same reason `read_all` does.
    """
    runner = runner or _powershell
    start_text = _windows_time(start)
    end_text = _windows_time(end)
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "try {"
        "  $e = Get-WinEvent -LogName '%s' -MaxEvents %d -ErrorAction Stop |"
        "       Where-Object { $_.TimeCreated -ge [datetime]'%s' -and $_.TimeCreated -le [datetime]'%s' };"
        "  $out = @();"
        "  if ($e) { $out = $e | ForEach-Object {"
        "    $x = [xml]$_.ToXml(); $pairs = @();"
        "    foreach ($d in $x.Event.EventData.Data) {"
        "      $pairs += ('<Data Name=\"' + $d.Name + '\">' + "
        "[System.Security.SecurityElement]::Escape([string]$d.'#text') + '</Data>') };"
        "    $mini = '<Event><EventData>' + ($pairs -join '') + '</EventData></Event>';"
        "    [pscustomobject]@{ Channel=$_.LogName; Id=$_.Id; Provider=$_.ProviderName;"
        "      Level=$_.LevelDisplayName; RecordId=$_.RecordId;"
        "      TimeCreated=$_.TimeCreated.ToString('o'); User=$_.UserId; Xml=$mini;"
        "      Message=$([string]$_.Message).Substring(0,[Math]::Min(1200,([string]$_.Message).Length)) } } };"
        "  [pscustomobject]@{ events=@($out); readable=$true } | ConvertTo-Json -Depth 5 -Compress"
        "} catch { [pscustomobject]@{ events=@(); readable=$false } | ConvertTo-Json -Depth 3 -Compress }"
    ) % (channel.replace("'", "''"), newest, start_text, end_text)
    text, reader_pid = runner(script, timeout=300)
    text = (text or "").strip()
    if not text:
        return [], False
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError:
        return [], False
    if isinstance(envelope, list):
        envelope = envelope[0] if envelope else {}
    if not envelope.get("readable"):
        return [], False
    raw = envelope.get("events") or []
    if isinstance(raw, dict):
        raw = [raw]
    events = []
    for item in raw:
        fields = _event_fields(item)
        if _is_reader_own(fields, _READER_PIDS | {reader_pid}):
            continue
        payload = windows_event_to_payload(item.get("Channel") or channel, item)
        payload["record_id"] = int(item.get("RecordId") or 0)
        payload["captured_channel"] = item.get("Channel") or channel
        events.append(payload)
    events.sort(key=lambda e: e.get("record_id") or 0)
    return events, True


def _windows_time(epoch: float) -> str:
    """An epoch as the local time string Get-WinEvent's filter wants."""
    import datetime
    return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%dT%H:%M:%S")


def capture_corpus(techniques=ALLOWED_TECHNIQUES, benign_windows: int = 3,
                   benign_seconds: float = 12.0, progress=print) -> dict:
    """Run every allowed technique and some benign windows, in one corpus."""
    reset_reader_pids()
    windows: list[Window] = []
    for index, technique in enumerate(techniques, 1):
        progress("  [%2d/%2d] %-11s %s" % (index, len(techniques), technique.attack_id,
                                           technique.name))
        window = run_technique(technique)
        progress("          -> %d event(s)" % len(window.events))
        windows.append(window)
    for index in range(benign_windows):
        progress("  benign window %d of %d (%.0fs of ordinary activity)"
                 % (index + 1, benign_windows, benign_seconds))
        window = capture_benign(benign_seconds, rotation=index)
        progress("          -> %d event(s)" % len(window.events))
        windows.append(window)
    return {
        "captured_at": time.time(),
        "settle_seconds": SETTLE_SECONDS,
        "techniques": [t.as_dict() for t in techniques],
        "windows": [w.as_dict() for w in windows],
    }
