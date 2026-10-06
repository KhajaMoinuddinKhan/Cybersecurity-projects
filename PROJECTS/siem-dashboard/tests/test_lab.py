"""The corpus harness, and the safety property that matters most about it.

The allowlist is the only thing standing between this project and running real
attack techniques on a real machine, so most of what follows is about it rather
than about the plumbing.
"""

from __future__ import annotations

import re

import pytest

from src.lab import (ALLOWED_TECHNIQUES, BENIGN, CaptureError, Technique,
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


def test_arguments_are_substituted_into_the_command():
    technique = Technique("T9999", "example", "an atomic", "command_prompt",
                          "run --flag #{value}", {"value": "abc"})
    assert technique.resolved() == "run --flag abc"
    assert "#{" not in technique.resolved()


def test_an_unsubstituted_argument_would_be_visible():
    technique = Technique("T9999", "example", "an atomic", "command_prompt", "run #{missing}")
    assert "#{missing}" in technique.resolved()


def test_the_reader_filter_recognises_its_own_process():
    """The harness must not score itself. Reading the log starts a process, and
    that process is in the log it is reading."""
    assert _is_reader_own({"ProcessId": "4242"}, 4242) is True
    assert _is_reader_own({"SourceProcessId": "4242"}, 4242) is True
    assert _is_reader_own({"ParentProcessId": "4242"}, 4242) is True
    assert _is_reader_own({"ProcessId": "4243"}, 4242) is False
    assert _is_reader_own({}, 4242) is False
    assert _is_reader_own({"ProcessId": ""}, 4242) is False


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
                           runner=lambda script, timeout: (_envelope([mine, theirs], []), 4242))
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
