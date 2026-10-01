"""A visible, consent-based keyboard event recorder for your own terminal.

This module deliberately records only the terminal in which it is running. It
has no background hook, persistence, network access, or hidden mode.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, TextIO


@dataclass(frozen=True)
class KeyEvent:
    """One key received by the foreground terminal."""

    timestamp: str
    key: str


def display_key(character: str) -> str:
    """Turn a terminal character into a readable label."""
    return {
        "\x1b": "ESC",
        "\r": "ENTER",
        "\n": "ENTER",
        "\t": "TAB",
        "\x7f": "BACKSPACE",
        "\b": "BACKSPACE",
        "\x03": "CTRL-C",
    }.get(character, character if character.isprintable() else f"U+{ord(character):04X}")


def iter_terminal_keys() -> Iterator[str]:
    """Yield keys from the foreground terminal until the caller stops.

    The terminal is restored even if the user presses Ctrl+C or the process
    fails. A non-interactive stdin is rejected so a redirected password or
    file is never silently recorded.
    """
    if not sys.stdin.isatty():
        raise RuntimeError("Keyboard recording requires an interactive terminal")

    if os.name == "nt":
        import msvcrt

        while True:
            character = msvcrt.getwch()
            if character in {"\x00", "\xe0"}:
                # Consume the second byte of a Windows special-key sequence.
                yield f"SPECIAL-{ord(msvcrt.getwch()):02X}"
            else:
                yield character
        return

    import termios
    import tty

    descriptor = sys.stdin.fileno()
    previous = termios.tcgetattr(descriptor)
    try:
        tty.setcbreak(descriptor)
        while True:
            yield sys.stdin.read(1)
    finally:
        termios.tcsetattr(descriptor, termios.TCSADRAIN, previous)


def record_session(output: Path, *, stop_key: str = "ESC", keys: Iterator[str] | None = None) -> int:
    """Record visible foreground-terminal keys as JSONL until ``stop_key``."""
    output.parent.mkdir(parents=True, exist_ok=True)
    source = keys if keys is not None else iter_terminal_keys()
    count = 0
    with output.open("a", encoding="utf-8") as handle:
        for raw_key in source:
            key = display_key(raw_key)
            event = KeyEvent(datetime.now(timezone.utc).isoformat(), key)
            handle.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
            handle.flush()
            count += 1
            if key.upper() == stop_key.upper():
                break
    return count


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Record visible keystrokes in this terminal with explicit consent."
    )
    parser.add_argument("--output", type=Path, default=Path("key-events.jsonl"))
    parser.add_argument(
        "--consent",
        action="store_true",
        help="Confirm that you own or are authorized to monitor this terminal.",
    )
    args = parser.parse_args()
    if not args.consent:
        raise SystemExit("Pass --consent after confirming you are authorized to record this terminal.")

    print("Visible terminal recording started. Press Esc to stop. Nothing is sent over the network.")
    try:
        count = record_session(args.output)
    except (OSError, RuntimeError) as exc:
        raise SystemExit(f"Keyboard recording failed: {exc}") from exc
    print(f"Recorded {count} terminal key events in {args.output}.")


if __name__ == "__main__":
    main()
