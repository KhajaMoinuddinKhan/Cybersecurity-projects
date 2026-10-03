"""Batch input, JSON output, and verbose mode on the command line."""
import json
import subprocess
import sys


def run_cli(*args, stdin=None):
    return subprocess.run(
        [sys.executable, "-m", "src.detector", *args],
        capture_output=True,
        text=True,
        input=stdin,
    )


def test_urls_are_read_from_a_file(tmp_path):
    listing = tmp_path / "urls.txt"
    listing.write_text(
        "# a comment\n\nhttps://example.com/about\nhttp://192.0.2.10/login/verify\n",
        encoding="utf-8",
    )
    result = run_cli("-f", str(listing))
    assert result.returncode == 0
    assert "https://example.com/about" in result.stdout
    assert "http://192.0.2.10/login/verify" in result.stdout
    assert "a comment" not in result.stdout


def test_urls_are_read_from_stdin_with_dash():
    result = run_cli("-f", "-", stdin="https://example.com/about\nhttp://a.co\n")
    assert result.returncode == 0
    assert "https://example.com/about" in result.stdout
    assert "http://a.co" in result.stdout


def test_urls_are_read_from_stdin_with_no_arguments():
    result = run_cli(stdin="https://example.com/about\n")
    assert result.returncode == 0
    assert "https://example.com/about" in result.stdout


def test_arguments_and_file_are_combined(tmp_path):
    listing = tmp_path / "urls.txt"
    listing.write_text("http://a.co\n", encoding="utf-8")
    result = run_cli("-f", str(listing), "https://example.com/about")
    assert result.returncode == 0
    assert "https://example.com/about" in result.stdout
    assert "http://a.co" in result.stdout


def test_json_mode_emits_parseable_output():
    result = run_cli("--json", "https://example.com/about", "http://192.0.2.10/login/verify")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["total"] == 2
    assert payload["summary"]["scored"] == 2
    assert payload["summary"]["low"] == 1
    assert payload["summary"]["medium"] == 1
    scored = [entry for entry in payload["results"] if "score" in entry]
    assert scored[1]["verdict"] == "medium"
    assert scored[0]["reasons"] == []


def test_json_mode_reports_invalid_urls():
    result = run_cli("--json", "http://[", "https://example.com/about")
    assert result.returncode != 0
    payload = json.loads(result.stdout)
    errors = [entry for entry in payload["results"] if "error" in entry]
    assert errors and errors[0]["url"] == "http://["
    assert payload["summary"]["scored"] == 1


def test_json_verbose_includes_unfired_signals():
    result = run_cli("--json", "--verbose", "https://example.com/about")
    assert result.returncode == 0
    entry = json.loads(result.stdout)["results"][0]
    assert "signals" in entry
    assert any(signal["fired"] is False for signal in entry["signals"])


def test_verbose_mode_names_signals_that_did_not_fire():
    result = run_cli("-v", "https://example.com/about")
    assert result.returncode == 0
    assert "Signals:" in result.stdout
    assert "[-] URL shortener" in result.stdout
    assert "[+]" not in result.stdout
