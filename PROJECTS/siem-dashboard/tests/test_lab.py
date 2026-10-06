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


def test_read_all_reports_a_channel_it_cannot_read():
    """A channel that does not exist must be reported, not silently dropped.

    The first version returned whatever came back, which on an unelevated shell
    meant a corpus missing Sysmon while looking complete.
    """
    payloads, unreadable = read_all(("No-Such-Channel-Exists",), {"No-Such-Channel-Exists": 0},
                                    newest=2)
    assert payloads == []
    assert unreadable == ["No-Such-Channel-Exists"]


def test_read_all_returns_a_pair_even_when_empty():
    result = read_all((), {}, newest=1)
    assert isinstance(result, tuple) and len(result) == 2
    assert result[0] == [] and result[1] == []


def test_the_benign_label_is_not_an_attack_id():
    assert BENIGN == "benign"
    assert all(t.attack_id != BENIGN for t in ALLOWED_TECHNIQUES)
