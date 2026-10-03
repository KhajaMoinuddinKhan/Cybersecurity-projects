"""Offline hash recovery using a wordlist and mangling rules supplied by the operator."""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import struct
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

ALGORITHMS = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "ntlm"}

# Hexadecimal digest lengths, including the Windows NTLM format. MD5 and NTLM
# are both 32 characters, so a digest of that length is ambiguous until one of
# the two is chosen explicitly.
DIGEST_LENGTHS = {
    "md5": 32,
    "ntlm": 32,
    "sha1": 40,
    "sha224": 56,
    "sha256": 64,
    "sha384": 96,
    "sha512": 128,
}

SALT_POSITIONS = ("suffix", "prefix")

# Mangling rules. These constants are the rule set the README documents, so the
# documentation and the code cannot drift apart.
NUMERIC_SUFFIXES = ("1", "12", "123", "1234")
PUNCTUATION_SUFFIXES = ("!", ".", "?", "@", "#")
LEET_SUBSTITUTIONS = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}

# Short brute force: lowercase letters and digits only, bounded so a run stays
# small enough to finish and be watched.
BRUTE_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
MAX_BRUTE_CANDIDATES = 2_000_000


def hashes_per_second(attempts: int, elapsed_seconds: float) -> float:
    """Candidates tested per second, or zero when no time was measured."""
    if elapsed_seconds <= 0:
        return 0.0
    return attempts / elapsed_seconds


@dataclass(frozen=True)
class CrackResult:
    algorithm: str
    attempts: int
    match: str | None
    elapsed_seconds: float
    target: str = ""
    salt: str | None = None
    salt_position: str | None = None

    @property
    def hashes_per_second(self) -> float:
        return hashes_per_second(self.attempts, self.elapsed_seconds)

    def as_dict(self) -> dict[str, Any]:
        """Render the result for the JSON report."""
        return {
            "target": self.target,
            "algorithm": self.algorithm,
            "salt": self.salt,
            "salt_position": self.salt_position,
            "attempts": self.attempts,
            "elapsed_seconds": self.elapsed_seconds,
            "hashes_per_second": self.hashes_per_second,
            "match": self.match,
        }


def require_algorithm(algorithm: str) -> str:
    """Normalize and validate an algorithm name before it reaches hashlib."""
    algorithm = algorithm.lower()
    if algorithm not in ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm {algorithm!r}; choose from {', '.join(sorted(ALGORITHMS))}"
        )
    return algorithm


def digest_size(algorithm: str) -> int:
    """Return a digest's length in bytes, including NTLM's 16-byte MD4."""
    algorithm = require_algorithm(algorithm)
    if algorithm == "ntlm":
        return 16
    return hashlib.new(algorithm).digest_size


def normalize_salt_position(position: str | None) -> str:
    """Validate the salt position, defaulting to an appended (suffix) salt."""
    if position is None:
        return "suffix"
    position = position.lower()
    if position not in SALT_POSITIONS:
        raise ValueError(
            f"Unsupported salt position {position!r}; choose from {', '.join(SALT_POSITIONS)}"
        )
    return position


def _md4_python(message: bytes) -> bytes:
    """Pure-Python MD4 (RFC 1320), used when OpenSSL does not expose MD4."""
    def rotate(value: int, amount: int) -> int:
        return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF

    def f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    data = bytearray(message)
    bit_length = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)
    data += struct.pack("<Q", bit_length)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for offset in range(0, len(data), 64):
        words = list(struct.unpack("<16I", data[offset:offset + 64]))
        start = (a, b, c, d)
        for index in range(4):
            base = index * 4
            a = rotate((a + f(b, c, d) + words[base]) & 0xFFFFFFFF, 3)
            d = rotate((d + f(a, b, c) + words[base + 1]) & 0xFFFFFFFF, 7)
            c = rotate((c + f(d, a, b) + words[base + 2]) & 0xFFFFFFFF, 11)
            b = rotate((b + f(c, d, a) + words[base + 3]) & 0xFFFFFFFF, 19)
        order2 = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
        for index in range(0, 16, 4):
            a = rotate((a + g(b, c, d) + words[order2[index]] + 0x5A827999) & 0xFFFFFFFF, 3)
            d = rotate((d + g(a, b, c) + words[order2[index + 1]] + 0x5A827999) & 0xFFFFFFFF, 5)
            c = rotate((c + g(d, a, b) + words[order2[index + 2]] + 0x5A827999) & 0xFFFFFFFF, 9)
            b = rotate((b + g(c, d, a) + words[order2[index + 3]] + 0x5A827999) & 0xFFFFFFFF, 13)
        order3 = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for index in range(0, 16, 4):
            a = rotate((a + h(b, c, d) + words[order3[index]] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
            d = rotate((d + h(a, b, c) + words[order3[index + 1]] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
            c = rotate((c + h(d, a, b) + words[order3[index + 2]] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
            b = rotate((b + h(c, d, a) + words[order3[index + 3]] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)
        a, b, c, d = ((a + start[0]) & 0xFFFFFFFF, (b + start[1]) & 0xFFFFFFFF,
                      (c + start[2]) & 0xFFFFFFFF, (d + start[3]) & 0xFFFFFFFF)
    return struct.pack("<4I", a, b, c, d)


def md4_digest(data: bytes) -> bytes:
    """Return the MD4 digest of the raw bytes, preferring the OpenSSL backend."""
    try:
        return hashlib.new("md4", data).digest()
    except ValueError:
        return _md4_python(data)


def ntlm_digest(candidate: str) -> str:
    """Hash a password the way Windows NTLM does: unsalted MD4 of UTF-16LE."""
    return md4_digest(candidate.encode("utf-16-le")).hex()


def digest_text(
    candidate: str,
    algorithm: str,
    salt: str | None = None,
    salt_position: str | None = None,
) -> str:
    """Hash one candidate, optionally with a salt appended or prepended."""
    algorithm = require_algorithm(algorithm)
    if algorithm == "ntlm":
        if salt:
            raise ValueError("NTLM hashes are unsalted; a salt cannot be applied to one")
        return ntlm_digest(candidate)
    if salt:
        position = normalize_salt_position(salt_position)
        material = candidate + salt if position == "suffix" else salt + candidate
    else:
        material = candidate
    return hashlib.new(algorithm, material.encode("utf-8")).hexdigest()


def validate_target(target: str, algorithm: str) -> str:
    """Validate and normalize a hexadecimal target digest."""
    target = target.strip().lower()
    expected_length = digest_size(algorithm) * 2
    if len(target) != expected_length or any(character not in "0123456789abcdef" for character in target):
        raise ValueError(f"Target is not a valid {algorithm} hexadecimal digest")
    return target


def detect_algorithms(digest: str) -> tuple[str, ...]:
    """List every algorithm whose digest length matches, by length and charset.

    A digest that is not hexadecimal, or whose length matches nothing supported,
    is rejected here rather than compared against the wrong algorithm.
    """
    digest = digest.strip().lower()
    if not digest or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError(f"Digest {digest!r} is not a hexadecimal digest")
    matches = tuple(sorted(name for name, length in DIGEST_LENGTHS.items() if length == len(digest)))
    if not matches:
        lengths = ", ".join(str(length) for length in sorted(set(DIGEST_LENGTHS.values())))
        raise ValueError(
            f"Digest length {len(digest)} matches no supported algorithm (supported hex lengths: {lengths})"
        )
    return matches


def resolve_algorithms(digest: str, algorithm: str | None = None, try_all: bool = False) -> tuple[str, ...]:
    """Choose the algorithm(s) to test a digest against.

    An explicit algorithm always wins. Otherwise the digest is detected, and an
    ambiguous digest is an error unless every plausible algorithm was requested.
    """
    if algorithm is not None:
        return (require_algorithm(algorithm),)
    detected = detect_algorithms(digest)
    if try_all or len(detected) == 1:
        return detected
    raise ValueError(
        f"Digest matches more than one algorithm ({', '.join(detected)}); pass --algorithm or --all"
    )


def _looks_like_digest(value: str) -> bool:
    try:
        detect_algorithms(value)
        return True
    except ValueError:
        return False


def parse_target(
    target: str,
    salt: str | None = None,
    salt_position: str | None = None,
) -> tuple[str, str | None, str | None]:
    """Split a target into its digest, salt and salt position.

    Supports a bare digest, an explicit ``--salt``, and the conventional
    ``hash:salt`` and ``salt:hash`` layouts. In ``hash:salt`` the salt is
    appended to the password (suffix); in ``salt:hash`` it is prepended.
    """
    target = target.strip()
    if salt is not None:
        if ":" in target:
            raise ValueError("A target that already carries a salt cannot also use --salt")
        return target, salt, normalize_salt_position(salt_position)
    if ":" not in target:
        return target, None, None
    parts = target.split(":")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Salted target {target!r} must be laid out as 'hash:salt' or 'salt:hash'")
    first, second = parts
    first_is_digest = _looks_like_digest(first)
    second_is_digest = _looks_like_digest(second)
    if first_is_digest and not second_is_digest:
        digest, embedded_salt, inferred = first, second, "suffix"
    elif second_is_digest and not first_is_digest:
        digest, embedded_salt, inferred = second, first, "prefix"
    elif first_is_digest and second_is_digest:
        chosen = normalize_salt_position(salt_position) if salt_position else None
        if chosen == "suffix":
            digest, embedded_salt, inferred = first, second, "suffix"
        elif chosen == "prefix":
            digest, embedded_salt, inferred = second, first, "prefix"
        else:
            raise ValueError(
                f"Salted target {target!r} is ambiguous between 'hash:salt' and 'salt:hash'; "
                "state --salt-position (suffix for hash:salt, prefix for salt:hash)"
            )
    else:
        raise ValueError(f"Salted target {target!r} contains no recognisable hexadecimal digest")
    position = normalize_salt_position(salt_position) if salt_position else inferred
    return digest, embedded_salt, position


def wordlist_candidates(path: Path) -> Iterator[str]:
    """Yield nonempty candidate lines without loading a wordlist into memory."""
    with path.open("r", encoding="utf-8-sig", errors="strict") as handle:
        for line in handle:
            candidate = line.rstrip("\r\n")
            if candidate:
                yield candidate


def brute_space(length: int) -> int:
    """Total number of lowercase-alphanumeric strings of length 1 to ``length``."""
    if length < 1:
        raise ValueError("--brute length must be at least 1")
    return sum(len(BRUTE_ALPHABET) ** size for size in range(1, length + 1))


def check_brute_length(length: int) -> int:
    """Return the brute-force search space, refusing an unreasonable one."""
    space = brute_space(length)
    if space > MAX_BRUTE_CANDIDATES:
        raise ValueError(
            f"--brute {length} would test {space:,} candidates, above the {MAX_BRUTE_CANDIDATES:,} limit; "
            "choose a smaller length"
        )
    return space


def brute_candidates(length: int) -> Iterator[str]:
    """Yield every lowercase-alphanumeric string up to ``length``, shortest first."""
    check_brute_length(length)
    for size in range(1, length + 1):
        for combination in itertools.product(BRUTE_ALPHABET, repeat=size):
            yield "".join(combination)


def rule_capitalise(word: str) -> list[str]:
    """Upper-case the first character and leave the rest untouched."""
    return [word[:1].upper() + word[1:]]


def rule_uppercase(word: str) -> list[str]:
    """Upper-case the whole word."""
    return [word.upper()]


def rule_append_numeric(word: str) -> list[str]:
    """Append each of the short numeric suffixes."""
    return [word + suffix for suffix in NUMERIC_SUFFIXES]


def rule_append_punctuation(word: str) -> list[str]:
    """Append each of the common punctuation suffixes."""
    return [word + suffix for suffix in PUNCTUATION_SUFFIXES]


def rule_leetspeak(word: str) -> list[str]:
    """Return one variant per leet substitution and one with every substitution."""
    variants = [
        word[:index] + LEET_SUBSTITUTIONS[character.lower()] + word[index + 1:]
        for index, character in enumerate(word)
        if character.lower() in LEET_SUBSTITUTIONS
    ]
    variants.append(
        "".join(LEET_SUBSTITUTIONS.get(character.lower(), character) for character in word)
    )
    return variants


RULES: tuple[tuple[str, Callable[[str], list[str]]], ...] = (
    ("capitalise", rule_capitalise),
    ("uppercase", rule_uppercase),
    ("append-numeric", rule_append_numeric),
    ("append-punctuation", rule_append_punctuation),
    ("leetspeak", rule_leetspeak),
)
RULE_NAMES = tuple(name for name, _ in RULES)


def mangle(word: str, rule_names: Iterable[str] | None = None) -> list[str]:
    """Return the base word plus its mangled variants, without duplicates."""
    selected = RULES if rule_names is None else tuple(rule for rule in RULES if rule[0] in set(rule_names))
    ordered = [word]
    for _, rule in selected:
        ordered.extend(rule(word))
    seen: set[str] = set()
    result: list[str] = []
    for candidate in ordered:
        if candidate and candidate not in seen:
            seen.add(candidate)
            result.append(candidate)
    return result


def candidate_stream(
    wordlist: Path | None = None,
    brute_length: int | None = None,
    use_rules: bool = False,
) -> Iterator[str]:
    """Yield candidates from the wordlist and/or the bounded brute-force space."""
    if wordlist is not None:
        for word in wordlist_candidates(wordlist):
            yield from mangle(word) if use_rules else (word,)
    if brute_length is not None:
        for word in brute_candidates(brute_length):
            yield from mangle(word) if use_rules else (word,)


def crack_hash(
    target: str,
    candidates: Iterable[str],
    algorithm: str = "sha256",
    salt: str | None = None,
    salt_position: str | None = None,
) -> CrackResult:
    """Try supplied candidates against one offline digest."""
    algorithm = require_algorithm(algorithm)
    target = validate_target(target, algorithm)
    position = normalize_salt_position(salt_position) if salt else None
    started = time.perf_counter()
    attempts = 0
    for candidate in candidates:
        attempts += 1
        if digest_text(candidate, algorithm, salt, salt_position) == target:
            return CrackResult(algorithm, attempts, candidate, time.perf_counter() - started, target, salt, position)
    return CrackResult(algorithm, attempts, None, time.perf_counter() - started, target, salt, position)


def crack_target(
    target: str,
    candidate_factory: Callable[[], Iterable[str]],
    algorithm: str | None = None,
    try_all: bool = False,
    salt: str | None = None,
    salt_position: str | None = None,
) -> list[CrackResult]:
    """Crack one target string, detecting the algorithm and salt layout.

    ``candidate_factory`` is called once per algorithm so the candidate stream
    can be replayed without holding a wordlist in memory.
    """
    digest, resolved_salt, resolved_position = parse_target(target, salt, salt_position)
    algorithms = resolve_algorithms(digest, algorithm, try_all)
    if resolved_salt is not None:
        algorithms = tuple(name for name in algorithms if name != "ntlm")
        if not algorithms:
            raise ValueError("NTLM hashes are unsalted; no usable algorithm for a salted target")
    return [
        replace(crack_hash(digest, candidate_factory(), name, resolved_salt, resolved_position), target=target)
        for name in algorithms
    ]


def crack_targets(
    targets: Iterable[str],
    candidate_factory: Callable[[], Iterable[str]],
    algorithm: str | None = None,
    try_all: bool = False,
    salt: str | None = None,
    salt_position: str | None = None,
) -> tuple[list[CrackResult], list[tuple[str, str]]]:
    """Crack several targets in one pass, keeping per-target errors separate."""
    results: list[CrackResult] = []
    errors: list[tuple[str, str]] = []
    for target in targets:
        try:
            results.extend(crack_target(target, candidate_factory, algorithm, try_all, salt, salt_position))
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append((target, str(exc)))
    return results, errors


def report_dict(results: list[CrackResult], errors: list[tuple[str, str]]) -> dict[str, Any]:
    """Assemble the JSON work report from the results and per-target errors."""
    total_attempts = sum(result.attempts for result in results)
    total_elapsed = sum(result.elapsed_seconds for result in results)
    return {
        "results": [result.as_dict() for result in results],
        "errors": [{"target": target, "error": message} for target, message in errors],
        "targets": len(results) + len(errors),
        "matched": sum(1 for result in results if result.match is not None),
        "total_attempts": total_attempts,
        "total_elapsed_seconds": total_elapsed,
        "total_hashes_per_second": hashes_per_second(total_attempts, total_elapsed),
    }


def print_result(result: CrackResult) -> None:
    """Print one target's measured work in the human-readable report."""
    print(f"Target: {result.target}")
    print(f"Algorithm: {result.algorithm}")
    if result.salt is not None:
        print(f"Salt: {result.salt} ({result.salt_position})")
    print(f"Candidates tested: {result.attempts}")
    print(f"Elapsed seconds: {result.elapsed_seconds:.6f}")
    print(f"Hashes per second: {result.hashes_per_second:.2f}")
    if result.match is None:
        print("No supplied candidate matched the target digest.")
    else:
        print(f"Match found: {result.match}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Recover a password from one or more offline hashes and supplied candidates.")
    parser.add_argument("targets", nargs="+", help="One or more hexadecimal digests, or hash:salt / salt:hash layouts, you are authorized to test")
    parser.add_argument("--wordlist", type=Path, help="File of candidate words, one per line")
    parser.add_argument("--algorithm", choices=sorted(ALGORITHMS), help="Digest algorithm; detected from each digest when omitted")
    parser.add_argument("--all", action="store_true", dest="try_all", help="Try every algorithm whose digest length matches")
    parser.add_argument("--salt", help="Salt applied to every candidate (combined with --salt-position)")
    parser.add_argument("--salt-position", choices=sorted(SALT_POSITIONS), help="Whether the salt is appended (suffix) or prepended (prefix)")
    parser.add_argument("--rules", action="store_true", help="Apply the documented mangling rules to each candidate")
    parser.add_argument("--brute", type=int, metavar="N", help="Also try every lowercase-alphanumeric string up to length N")
    parser.add_argument("--json", action="store_true", help="Print a JSON work report instead of text")
    args = parser.parse_args()

    if args.wordlist is None and args.brute is None:
        raise SystemExit("Provide --wordlist, --brute N, or both.")
    if args.wordlist is not None and not args.wordlist.is_file():
        raise SystemExit(f"Wordlist not found: {args.wordlist}")
    if args.brute is not None:
        try:
            check_brute_length(args.brute)
        except ValueError as exc:
            raise SystemExit(f"Hash recovery failed: {exc}") from exc

    def candidate_factory() -> Iterator[str]:
        return candidate_stream(args.wordlist, args.brute, args.rules)

    results, errors = crack_targets(
        args.targets, candidate_factory, args.algorithm, args.try_all, args.salt, args.salt_position
    )

    if args.json:
        print(json.dumps(report_dict(results, errors), indent=2))
    else:
        for target, message in errors:
            print(f"Target: {target}")
            print(f"Error: {message}")
            print()
        for result in results:
            print_result(result)
            print()
        if len(args.targets) > 1:
            matched = sum(1 for result in results if result.match is not None)
            print(f"Matched {matched} of {len(args.targets)} target digests.")

    if errors or not any(result.match is not None for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
