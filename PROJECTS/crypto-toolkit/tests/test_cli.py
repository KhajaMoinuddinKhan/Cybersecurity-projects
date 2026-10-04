"""The command line, which exists to exercise the primitives without writing Python.

Every test here drives ``cli.main`` with an argument list and reads what comes
back, which is the same path a person takes. The point is not that the verbs are
clever -- they are deliberately thin -- but that the published vectors can be
re-checked from a shell, and that a tampered ciphertext is refused there too.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import cli  # noqa: E402

KEY = "feffe9928665731c6d6a8f9467308308"
NONCE = "cafebabefacedbaddecaf888"


def test_the_published_vectors_pass_through_the_command_line(capsys):
    assert cli.main(["vectors"]) == 0
    out = capsys.readouterr().out
    assert "4 of 4 published vectors reproduced" in out
    assert "MISMATCH" not in out


def test_hash_agrees_with_the_published_digest(tmp_path, capsys):
    path = tmp_path / "abc.txt"
    path.write_bytes(b"abc")
    assert cli.main(["hash", str(path)]) == 0
    assert capsys.readouterr().out.strip() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_hash_reads_standard_input(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", type("S", (), {"buffer": __import__("io").BytesIO(b"abc")})())
    assert cli.main(["hash", "-"]) == 0
    assert capsys.readouterr().out.strip().startswith("ba7816bf")


def test_hmac_matches_the_published_vector(capsys):
    assert cli.main(["hmac", "4a65666", "what do ya want for nothing?"]) == 2  # odd-length hex is refused
    assert "must be hex" in capsys.readouterr().err
    assert cli.main(["hmac", "4a656665", "what do ya want for nothing?"]) == 0
    assert capsys.readouterr().out.strip() == (
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )


def test_seal_then_open_round_trips(tmp_path, capsys):
    source = tmp_path / "plain.txt"
    source.write_bytes(b"a message that has to survive the trip")
    assert cli.main(["seal", KEY, NONCE, str(source)]) == 0
    printed = capsys.readouterr().out.split()
    ciphertext, tag = printed[1], printed[3]

    target = tmp_path / "back.txt"
    assert cli.main(["open", KEY, NONCE, ciphertext, tag, "--out", str(target)]) == 0
    assert target.read_bytes() == source.read_bytes()
    capsys.readouterr()  # the --out run reports a byte count; drop it

    assert cli.main(["open", KEY, NONCE, ciphertext, tag]) == 0
    assert capsys.readouterr().out.split()[1] == source.read_bytes().hex()


def test_open_refuses_a_tampered_tag(capsys):
    # The published case 2, whose key and nonce are both all-zero.
    zero_key = "00" * 16
    zero_nonce = "00" * 12
    ciphertext = "0388dace60b6a392f328c2b971b2fe78"
    assert cli.main(["open", zero_key, zero_nonce, ciphertext, "ab6e47d42cec13bdf53a67b21257bddf"]) == 0
    assert capsys.readouterr().out.split()[1] == "00" * 16
    assert cli.main(["open", zero_key, zero_nonce, ciphertext, "ab6e47d42cec13bdf53a67b21257bdde"]) == 1
    assert "refused" in capsys.readouterr().err
    # And the same ciphertext under the wrong key is refused too.
    assert cli.main(["open", KEY, NONCE, ciphertext, "ab6e47d42cec13bdf53a67b21257bddf"]) == 1
    assert "refused" in capsys.readouterr().err


def test_a_bad_hex_argument_is_reported_not_raised(capsys):
    assert cli.main(["hmac", "zz", "message"]) == 2
    assert "must be hex" in capsys.readouterr().err
    assert cli.main(["seal", "00", NONCE, "-"]) == 2
    assert "key" in capsys.readouterr().err.lower()


def test_a_missing_file_is_reported_not_raised(tmp_path, capsys):
    assert cli.main(["hash", str(tmp_path / "absent.bin")]) == 2
    assert "could not read" in capsys.readouterr().err
