"""Offline hash recovery using a wordlist supplied by the operator."""
from __future__ import annotations

import argparse
import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

ALGORITHMS = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}


@dataclass(frozen=True)
class CrackResult:
    algorithm: str
    attempts: int
    match: str | None
    elapsed_seconds: float


def require_algorithm(algorithm: str) -> str:
    """Normalize and validate an algorithm name before it reaches hashlib."""
    algorithm = algorithm.lower()
    if algorithm not in ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm {algorithm!r}; choose from {', '.join(sorted(ALGORITHMS))}"
        )
    return algorithm


def digest_text(candidate: str, algorithm: str) -> str:
    """Hash one candidate encoded as UTF-8."""
    return hashlib.new(require_algorithm(algorithm), candidate.encode("utf-8")).hexdigest()


def validate_target(target: str, algorithm: str) -> str:
    """Validate and normalize a hexadecimal target digest."""
    target = target.strip().lower()
    expected_length = hashlib.new(require_algorithm(algorithm)).digest_size * 2
    if len(target) != expected_length or any(character not in "0123456789abcdef" for character in target):
        raise ValueError(f"Target is not a valid {algorithm} hexadecimal digest")
    return target


def wordlist_candidates(path: Path) -> Iterator[str]:
    """Yield nonempty candidate lines without loading a wordlist into memory."""
    with path.open("r", encoding="utf-8-sig", errors="strict") as handle:
        for line in handle:
            candidate = line.rstrip("\r\n")
            if candidate:
                yield candidate


def crack_hash(target: str, candidates: Iterable[str], algorithm: str = "sha256") -> CrackResult:
    """Try supplied candidates against one offline digest."""
    algorithm = require_algorithm(algorithm)
    target = validate_target(target, algorithm)
    started = time.perf_counter()
    attempts = 0
    for candidate in candidates:
        attempts += 1
        if digest_text(candidate, algorithm) == target:
            return CrackResult(algorithm, attempts, candidate, time.perf_counter() - started)
    return CrackResult(algorithm, attempts, None, time.perf_counter() - started)


def main() -> None:
    parser = argparse.ArgumentParser(description="Recover a password from an offline hash and supplied wordlist.")
    parser.add_argument("target", help="The hexadecimal digest you are authorized to test")
    parser.add_argument("--wordlist", type=Path, required=True)
    parser.add_argument("--algorithm", choices=sorted(ALGORITHMS), default="sha256")
    args = parser.parse_args()
    if not args.wordlist.is_file():
        raise SystemExit(f"Wordlist not found: {args.wordlist}")
    try:
        result = crack_hash(args.target, wordlist_candidates(args.wordlist), args.algorithm)
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(f"Hash recovery failed: {exc}") from exc
    print(f"Algorithm: {result.algorithm}")
    print(f"Candidates tested: {result.attempts}")
    print(f"Elapsed seconds: {result.elapsed_seconds:.6f}")
    if result.match is None:
        print("No supplied candidate matched the target digest.")
        raise SystemExit(1)
    print(f"Match found: {result.match}")


if __name__ == "__main__":
    main()
