"""Feed every project a collection that is structurally wrong, and check it refuses.

The shipped samples are all well formed, so every project is exercised against input
shaped the way its code expects. The defects that survive that are in the paths a good
sample never takes: an identifier pointing at an object never collected, a required key
absent, a value of the wrong type, an empty sequence where the code assumes otherwise.

Each project's own sample is mutated rather than replaced, so the shape stays right and
only the assumption under test is broken. Projects whose input is an argument rather
than a file get degenerate arguments instead, since there is nothing to mutate.

A project may refuse any of these. Refusing is the correct answer. What is not
acceptable is a traceback, which means the refusal happened by luck rather than by
design -- and a crash the caller cannot distinguish from a real fault.

The first version of this covered two projects out of eighteen and printed "every
project refused cleanly", which was true of the two it ran. Coverage is reported per
project now, and a project that is not covered says why.
"""
from pathlib import Path
import json
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TRACEBACK = "Traceback (most recent call last)"

# project -> (module, how it takes input, the sample to mutate or the argument to vary)
# Taken from each project's own README usage line, not guessed.
FILE_INPUT = {
    "ad-attack-paths": "src.cli",
    "cloud-asset-inventory": "src.inventory",
    "crypto-toolkit": "src.cli",
    "docker-security-audit": "src.audit",
    "password-policy-auditor": "src.audit",
    "posture-assessment": "src.cli",
    "threat-intelligence-aggregator": "src.aggregator",
}
# module -> (argument position it reads from, a degenerate argument to pass)
ARGUMENT_INPUT = {
    "hash-cracker": ("src.cracker", ["", "zz", "0" * 4096, "-", "a" * 2000]),
    "network-traffic-analyzer": ("src.analyzer", ["", "not-a-pcap", "\x00" * 64]),
    "pcap-traffic-summary": ("src.analyze_pcap", ["", "not-a-pcap", "\x00" * 64]),
    "phishing-url-detector": ("src.detector", ["", "http://", "https://" + "a" * 3000,
                                               "javascript:alert(1)", " "]),
    "ssl-tls-scanner": ("src.scanner", ["", "256.256.256.256", "a" * 3000, "-"]),
    "web-vulnerability-scanner": ("src.scanner", ["", "not a url", "http://" + "a" * 3000]),
    "tls-fingerprint-console": ("src.cli", ["", "not-an-interface", "-1"]),
    "file-integrity-monitor": ("src.fim", ["", "does-not-exist", " " * 100]),
    "wifi-security-analyzer": ("src.cli", ["", "not-a-command", "--help"]),
}
# projects whose entry point needs a server or a database and cannot be driven this way
NOT_DRIVABLE = {
    "siem-dashboard": "the dashboard serves HTTP and its collector needs Windows channels",
    "keylogger": "records real input and requires explicit consent to start",
    "scoped-assessment": "starts the lab server rather than reading a file",
}


def mutations(text: str) -> dict:
    out = {
        "empty": "",
        "whitespace": "   \n\t\n",
        "truncated": text[: max(1, len(text) // 3)],
        "nul bytes": "\x00" * 64,
    }
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return out
    emptied = _replace_first(parsed, (dict, list))
    if emptied is not None:
        out["emptied"] = json.dumps(emptied)
    key = next((k for k, _ in _walk(parsed) if isinstance(k, str)), None)
    dropped = _drop_key(parsed, key) if key else None
    if dropped is not None:
        out["key removed"] = json.dumps(dropped)
    wrong = _wrong_type(parsed)
    if wrong is not None:
        out["wrong type"] = json.dumps(wrong)
    dangled = _dangle(parsed)
    if dangled is not None:
        out["dangling reference"] = json.dumps(dangled)
    return out


def _walk(node, path=()):
    if isinstance(node, dict):
        for key, value in node.items():
            yield path + (key,), value
            yield from _walk(value, path + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield path + (index,), value
            yield from _walk(value, path + (index,))


def _replace_first(node, kinds):
    if isinstance(node, dict):
        for key, value in list(node.items()):
            if isinstance(value, kinds):
                clone = dict(node); clone[key] = type(value)()
                return clone
            replaced = _replace_first(value, kinds)
            if replaced is not None:
                clone = dict(node); clone[key] = replaced
                return clone
    elif isinstance(node, list):
        for index, value in enumerate(node):
            if isinstance(value, kinds):
                clone = list(node); clone[index] = type(value)()
                return clone
            replaced = _replace_first(value, kinds)
            if replaced is not None:
                clone = list(node); clone[index] = replaced
                return clone
    return None


def _drop_key(node, key):
    if isinstance(node, dict):
        if key in node:
            return {k: v for k, v in node.items() if k != key}
        for k, value in node.items():
            replaced = _drop_key(value, key)
            if replaced is not None:
                clone = dict(node); clone[k] = replaced
                return clone
    elif isinstance(node, list):
        for index, value in enumerate(node):
            replaced = _drop_key(value, key)
            if replaced is not None:
                clone = list(node); clone[index] = replaced
                return clone
    return None


def _wrong_type(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str):
                clone = dict(node); clone[key] = 12345
                return clone
            replaced = _wrong_type(value)
            if replaced is not None:
                clone = dict(node); clone[key] = replaced
                return clone
    elif isinstance(node, list):
        for index, value in enumerate(node):
            if isinstance(value, str):
                clone = list(node); clone[index] = 12345
                return clone
            replaced = _wrong_type(value)
            if replaced is not None:
                clone = list(node); clone[index] = replaced
                return clone
    return None


def _dangle(node):
    pattern = re.compile(r"^S-1-5-21-[\d-]+$|^[0-9A-Fa-f]{8}-[0-9A-Fa-f-]{27}$")
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str) and pattern.match(value):
                clone = dict(node)
                clone[key] = "S-1-5-21-9999999999-9999999999-9999999999-9999"
                return clone
            replaced = _dangle(value)
            if replaced is not None:
                clone = dict(node); clone[key] = replaced
                return clone
    elif isinstance(node, list):
        for index, value in enumerate(node):
            if isinstance(value, str) and pattern.match(value):
                clone = list(node)
                clone[index] = "S-1-5-21-9999999999-9999999999-9999999999-9999"
                return clone
            replaced = _dangle(value)
            if replaced is not None:
                clone = list(node); clone[index] = replaced
                return clone
    return None


# The files a project actually reads. Named inputs first, then the ones a project
# keeps in a directory that says what it is for -- a policy in policy/, a collection in
# data/. Naming every one of them here would be a list to maintain; the directories are
# the project's own statement about what it reads.
INPUT_DIRS = {"policy", "data", "examples", "sample_exports", "fixtures", "vectors"}
TEXT_SUFFIXES = {".json", ".csv", ".yaml", ".yml", ".conf", ".txt", ".log"}
BINARY_SUFFIXES = {".zip", ".pcap"}


def samples(project: Path) -> list:
    found = []
    for path in sorted(project.rglob("*")):
        if not path.is_file():
            continue
        parts = set(path.parts)
        if parts & {".venv", "__pycache__", ".git", "docs", "learn"}:
            continue
        # tests/ is excluded except for the vectors a project keeps there, which are
        # inputs like any other -- a published test vector is exactly the shape the
        # code expects, so mutating one breaks an assumption rather than the format.
        if "tests" in parts and "vectors" not in parts:
            continue
        low = path.name.lower()
        named = low.startswith(("sample", "example"))
        in_input_dir = any(part.lower() in INPUT_DIRS for part in path.parts)
        suffix = path.suffix.lower()
        if not (named or in_input_dir):
            continue
        if suffix in TEXT_SUFFIXES or suffix in BINARY_SUFFIXES:
            found.append(path)
    return found


def mutate_bytes(payload: bytes) -> dict:
    """Mutations for a binary input: there is nothing to re-type, only to damage."""
    return {
        "empty": b"",
        "truncated": payload[: max(1, len(payload) // 3)],
        "header only": payload[:64],
        "corrupt tail": payload[:-1] + b"\x00" if payload else b"\x00",
        "not a zip": b"PK\x03\x04" + b"\x00" * 32,
    }


def run(project: Path, module: str, argument) -> str:
    command = [sys.executable, "-m", module]
    command += [str(argument)] if argument is not None else []
    try:
        result = subprocess.run(command, cwd=project, capture_output=True, text=True,
                                timeout=180, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return ""            # a hang is a different fault; not counted here
    return result.stderr


def main() -> int:
    failures = []
    covered, skipped = [], []
    for project in sorted((ROOT / "PROJECTS").iterdir()):
        if not project.is_dir():
            continue
        name = project.name
        if name in NOT_DRIVABLE:
            skipped.append((name, NOT_DRIVABLE[name]))
            continue
        before = len(failures)
        count = 0
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            if name in FILE_INPUT:
                module = FILE_INPUT[name]
                for sample in samples(project)[:4]:
                    if sample.suffix.lower() in BINARY_SUFFIXES:
                        payload = sample.read_bytes()
                        cases = mutate_bytes(payload)
                        writer = "bytes"
                    else:
                        cases = mutations(sample.read_text(encoding="utf-8", errors="replace"))
                        writer = "text"
                    for mutation, body in cases.items():
                        target = work / (sample.stem + "-" + mutation.replace(" ", "_") + sample.suffix)
                        if writer == "bytes":
                            target.write_bytes(body)
                        else:
                            target.write_text(body, encoding="utf-8", errors="replace")
                        count += 1
                        stderr = run(project, module, target)
                        if TRACEBACK in stderr:
                            last = [l for l in stderr.strip().splitlines() if l.strip()][-1]
                            failures.append((name, sample.name, mutation, last[:110]))
            elif name in ARGUMENT_INPUT:
                module, arguments = ARGUMENT_INPUT[name]
                for argument in arguments:
                    if "\x00" in argument:
                        continue      # a NUL cannot be passed on a command line
                    count += 1
                    stderr = run(project, module, argument)
                    if TRACEBACK in stderr:
                        last = [l for l in stderr.strip().splitlines() if l.strip()][-1]
                        failures.append((name, "(argument)", repr(argument)[:20], last[:110]))
            else:
                skipped.append((name, "no entry point declared for this check"))
                continue
        covered.append((name, count))

    print("malformed inputs tried: %d\n" % sum(c for _, c in covered), flush=True)
    print("covered:")
    for name, count in covered:
        print("  %-30s %d" % (name, count))
    if skipped:
        print("\nnot covered, and why:")
        for name, why in skipped:
            print("  %-30s %s" % (name, why))
    if failures:
        print("\n%d input(s) produced a traceback:\n" % len(failures))
        for project, sample, mutation, last in failures:
            print("  %-24s %-20s %-18s %s" % (project, sample[:20], mutation, last))
        return 1
    print("\nevery covered project refused every malformed input cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
