"""The corpus harness, and the safety property that matters most about it.

The allowlist is the only thing standing between this project and running real
attack techniques on a real machine, so most of what follows is about it rather
than about the plumbing.
"""

from __future__ import annotations

import re

import pytest

from src.lab import (ALLOWED_TECHNIQUES, BENIGN, BENIGN_WORKLOAD, CaptureError, Technique,
                     read_window,
                     _event_fields, _is_reader_own, read_all)


def test_every_allowed_technique_is_read_only():
    """No command may reach the network, change the machine, or need elevation.

    This is the test the module exists to pass. The atomics tree contains
    "WinPwn" tests under the same techniques that download and execute
    PowerShell from a URL, and one of them appearing here would be a genuine
    incident rather than a failing assertion.
    """
    network = re.compile(r"(downloadstring|invoke-webrequest|net\.webclient|\biex\b|"
                         r"invoke-expression|http://|https://|curl |wget |bitsadmin)", re.I)
    mutates = re.compile(r"(\breg add\b|\breg delete\b|new-item|remove-item|set-itemproperty|"
                         r"out-file|\bsc\.exe|schtasks|netsh \w+ set|copy-item|move-item|"
                         r"add-localgroupmember|stop-process|start-process)", re.I)
    for technique in ALLOWED_TECHNIQUES:
        command = technique.resolved()
        assert not network.search(command), (technique.name, "reaches the network")
        assert not mutates.search(command), (technique.name, "changes the machine")
        assert "#{" not in command, (technique.name, "an argument was left unsubstituted")


def test_every_technique_carries_its_provenance():
    """Each entry names the Atomic test it came from, so the claim is checkable."""
    for technique in ALLOWED_TECHNIQUES:
        assert technique.attack_id.startswith("T")
        assert technique.name and technique.atomic
        assert technique.executor in ("command_prompt", "powershell")


def test_the_allowlist_covers_more_than_one_technique():
    assert len(ALLOWED_TECHNIQUES) >= 8
    assert len({t.attack_id for t in ALLOWED_TECHNIQUES}) >= 4


def test_the_command_text_comes_from_the_vendored_tree():
    """No command is stored in this repository's own source.

    The atomics tree is the source of the text; `src/lab.py` holds only a list of
    the atomic guids that are allowed. That distinction is what stops the lab
    drifting from the atomics, which it had: the hard-coded copy of T1082's
    system-information test had quietly been replaced with a read-only command,
    and the tree's actual test for that name runs a script that writes a report
    file.
    """
    from src.lab import Technique, ATOMIC_SOURCE
    import dataclasses
    fields = {f.name for f in dataclasses.fields(Technique)}
    assert "command" not in fields and "executor" not in fields
    assert {"attack_id", "name", "guid"} <= fields
    assert ATOMIC_SOURCE.exists(), "the atomics must be vendored"
    assert list(ATOMIC_SOURCE.glob("*.yaml")), "the atomics must be vendored"


def test_every_allowed_technique_resolves_from_the_tree():
    for technique in ALLOWED_TECHNIQUES:
        assert technique.resolved().strip(), technique.guid
        assert technique.executor in ("command_prompt", "powershell"), technique.guid
        assert "#{" not in technique.resolved(), (technique.name, "an argument is unfilled")


def test_arguments_come_from_the_atomic_not_from_this_file():
    """`whoami /all` -- the `/all` is the atomic's own declared default."""
    whoami = next(t for t in ALLOWED_TECHNIQUES if t.attack_id == "T1033")
    assert whoami.arguments == {}, "no argument is overridden here"
    assert "/all" in whoami.resolved()


def test_a_selector_that_does_not_resolve_fails_loudly():
    """A stale guid must stop the lab, not silently run something else.

    Two different Windows tests in T1082 are both named "System Information
    Discovery", so a name is not an identity. Keying on the atomic's guid means a
    rename cannot quietly change what runs.
    """
    from src.lab import Technique, CaptureError
    bogus = Technique("T1082", "nothing", "00000000-0000-0000-0000-000000000000")
    with pytest.raises(CaptureError):
        bogus.resolved()
    unknown_technique = Technique("T9999", "nothing", "66703791-c902-4560-8770-42b8a91f7667")
    with pytest.raises(CaptureError):
        unknown_technique.resolved()


def test_the_allowlist_excludes_the_atomics_that_download_code():
    """The WinPwn tests are in the same file as the safe ones, and stay out.

    They are under the same technique ids and fetch PowerShell from
    raw.githubusercontent.com. They are excluded by guid, which is the only
    stable way to say so.
    """
    import yaml
    from src.lab import ATOMIC_SOURCE, ALLOWED_TECHNIQUES
    allowed = {t.guid for t in ALLOWED_TECHNIQUES}
    offenders = []
    for path in ATOMIC_SOURCE.glob("*.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for test in data.get("atomic_tests") or []:
            guid = str(test.get("auto_generated_guid") or "")
            command = str((test.get("executor") or {}).get("command") or "")
            if guid in allowed and "raw.githubusercontent.com" in command:
                offenders.append((path.name, test.get("name")))
    assert not offenders, offenders


def test_the_reader_filter_recognises_its_own_process():
    """The harness must not score itself. Reading the log starts a process, and
    that process is in the log it is reading."""
    assert _is_reader_own({"ProcessId": "4242"}, {4242}) is True
    assert _is_reader_own({"SourceProcessId": "4242"}, {4242}) is True
    assert _is_reader_own({"ParentProcessId": "4242"}, {4242}) is True
    assert _is_reader_own({"ProcessId": "4243"}, {4242}) is False
    assert _is_reader_own({}, {4242}) is False
    assert _is_reader_own({"ProcessId": ""}, {4242}) is False
    assert _is_reader_own({"ProcessId": "4242"}, set()) is False


def test_the_filter_knows_every_reader_not_just_the_current_one():
    """The reader that captured an event is rarely the one that produced it.

    The marks query and the previous window's read both leave processes behind,
    and a filter that only knew the current pid left all of them in the corpus.
    """
    assert _is_reader_own({"ProcessId": "11"}, {11, 22, 33}) is True
    assert _is_reader_own({"ProcessId": "33"}, {11, 22, 33}) is True
    assert _is_reader_own({"ProcessId": "44"}, {11, 22, 33}) is False


def test_reader_pids_accumulate_and_can_be_reset():
    """The memory is what makes the previous test possible."""
    import src.lab as lab
    lab.reset_reader_pids()
    assert lab.reader_pids() == set()
    lab._READER_PIDS.add(4242)
    assert 4242 in lab.reader_pids()
    lab.reset_reader_pids()
    assert lab.reader_pids() == set()


def test_event_fields_reads_event_data_out_of_the_xml():
    xml = ('<Event><EventData>'
           '<Data Name="Image">C:\\Windows\\cmd.exe</Data>'
           '<Data Name="ProcessId">99</Data>'
           '</EventData></Event>')
    fields = _event_fields({"Xml": xml})
    assert fields["Image"] == r"C:\Windows\cmd.exe"
    assert fields["ProcessId"] == "99"


def _envelope(events, unreadable):
    import json as _json
    return _json.dumps({"events": events, "unreadable": unreadable})


def test_read_all_reports_a_channel_it_cannot_read():
    """A channel that does not exist must be reported, not silently dropped.

    The first version returned whatever came back, which on an unelevated shell
    meant a corpus missing Sysmon while looking complete. The runner is injected
    so this holds on any platform: the harness is Windows-only, but the promise
    it makes about its own output is not.
    """
    payloads, unreadable = read_all(("Sysmon", "Security"), {"Sysmon": 0, "Security": 0},
                                    newest=2,
                                    runner=lambda script, timeout: (_envelope([], ["Security"]), 1))
    assert payloads == []
    assert unreadable == ["Security"]


def test_read_all_keeps_the_events_it_did_read():
    """A readable channel's records come back, newest last, marks respected."""
    record = {"Channel": "System", "Id": 1, "Level": "Information", "RecordId": 20,
              "TimeCreated": "2026-10-07T12:00:00", "User": "u", "Message": "m",
              "Xml": '<Event><EventData><Data Name="Image">C:\\a.exe</Data></EventData></Event>'}
    older = dict(record, RecordId=5)
    payloads, unreadable = read_all(("System",), {"System": 10}, newest=5,
                                    runner=lambda script, timeout: (_envelope([older, record], []), 1))
    assert unreadable == []
    assert [p["record_id"] for p in payloads] == [20]      # the pre-mark record is dropped


def test_read_all_drops_events_belonging_to_the_reader():
    """The harness must not measure itself. A record whose ProcessId is the
    reading process is the apparatus, not the behaviour."""
    mine = {"Channel": "System", "Id": 1, "Level": "Information", "RecordId": 30,
            "TimeCreated": "2026-10-07T12:00:00", "User": "u", "Message": "m",
            "Xml": '<Event><EventData><Data Name="ProcessId">4242</Data></EventData></Event>'}
    theirs = dict(mine, RecordId=31,
                  Xml='<Event><EventData><Data Name="ProcessId">99</Data></EventData></Event>')
    payloads, _ = read_all(("System",), {"System": 10}, newest=5,
                           runner=lambda script, timeout: (_envelope([mine, theirs], []), 4242),
                           exclude_pids={4242})
    assert [p["record_id"] for p in payloads] == [31]


def test_read_all_refuses_an_empty_read():
    """Nothing at all is a failure, not an empty corpus."""
    with pytest.raises(CaptureError):
        read_all(("System",), {"System": 0}, newest=5,
                 runner=lambda script, timeout: ("   ", 1))


def test_read_all_returns_a_pair_even_when_empty():
    result = read_all((), {}, newest=1)
    assert isinstance(result, tuple) and len(result) == 2
    assert result[0] == [] and result[1] == []


def test_the_benign_label_is_not_an_attack_id():
    assert BENIGN == "benign"
    assert all(t.attack_id != BENIGN for t in ALLOWED_TECHNIQUES)


def test_the_benign_workload_is_ordinary_and_safe():
    """The baseline has to contain process creation, and nothing harmful.

    A benign window with nothing running in it is not a baseline, it is an
    absence -- and a detector asked whether a command is unusual for this host
    cannot answer from data in which the host ran no commands. So the workload
    exists. It also has to be safe: this is ordinary activity, not a technique.
    """
    assert len(BENIGN_WORKLOAD) >= 5
    network = re.compile(r"(downloadstring|invoke-webrequest|net\.webclient|\biex\b|"
                         r"invoke-expression|https?://|curl |wget )", re.I)
    mutates = re.compile(r"(\breg add\b|\breg delete\b|new-item|remove-item|out-file|"
                         r"schtasks|netsh \w+ set|copy-item|move-item|stop-process)", re.I)
    for executor, command in BENIGN_WORKLOAD:
        assert executor in ("command_prompt", "powershell")
        assert not network.search(command), (command, "reaches the network")
        assert not mutates.search(command), (command, "changes the machine")


def test_the_benign_workload_contains_an_overlap_on_purpose():
    """One command in it is also a discovery technique.

    `ipconfig` is T1016 and it is also what somebody types when the wifi looks
    wrong. A baseline with no such command in it would make the detection problem
    look easier than it is, so the overlap is deliberate and asserted.
    """
    commands = " ".join(command for _, command in BENIGN_WORKLOAD).lower()
    assert "ipconfig" in commands


def test_the_benign_workload_is_not_the_technique_list():
    """No technique's command may appear in the baseline."""
    baseline = " ".join(command for _, command in BENIGN_WORKLOAD).lower()
    for technique in ALLOWED_TECHNIQUES:
        command = technique.resolved().lower()
        if technique.attack_id == "T1016":
            continue                     # the deliberate overlap, asserted above
        assert command not in baseline, (technique.attack_id, "is in the baseline")


def test_read_window_reports_a_channel_it_could_not_read():
    """Time-based windows exist because two processes have to take them.

    Reading Sysmon needs elevation; spawning the techniques must not have it,
    because endpoint protection refuses the encoded-PowerShell atomic from an
    elevated parent. Record-id marks cannot be taken by a process that is not
    there when the technique runs, so the windows are timestamps instead.
    """
    events, readable = read_window("Sysmon", 0.0, 1.0,
                                   runner=lambda script, timeout: ('{"events": [], "readable": false}', 1))
    assert events == [] and readable is False


def test_read_window_returns_the_events_when_the_channel_reads():
    import json as _json
    envelope = _json.dumps({
        "events": [{"Channel": "System", "Id": 1, "RecordId": 5,
                    "TimeCreated": "2026-10-07T12:00:00", "Message": "m",
                    "Xml": '<Event><EventData><Data Name="Image">C:\\a.exe</Data></EventData></Event>'}],
        "readable": True,
    })
    events, readable = read_window("System", 0.0, 1.0,
                                   runner=lambda script, timeout: (envelope, 1))
    assert readable is True
    assert len(events) == 1 and events[0]["record_id"] == 5


def test_read_window_refuses_an_empty_answer():
    events, readable = read_window("System", 0.0, 1.0,
                                   runner=lambda script, timeout: ("", 1))
    assert events == [] and readable is False
