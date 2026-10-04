"""The command line over the primitives.

This is a demonstration surface rather than a tool anyone should build on: it
exists so that the primitives can be exercised without writing Python, and so
that the published vectors can be re-checked on any machine with one command.
Keys and nonces are given as hex on the command line, which is fine for a test
vector and wrong for anything real -- a command line is visible to every other
process on the machine. The README says so as well.
"""

from __future__ import annotations

import argparse
import sys

from .gcm import GCM, InvalidTag
from .hmac import hmac_sha256_hex
from .sha256 import sha256_hex


def _hex(value: str, what: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("%s must be hex: %s" % (what, exc)) from exc


def _read(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise ValueError("could not read %s: %s" % (path, exc)) from exc


def cmd_hash(args) -> int:
    print(sha256_hex(_read(args.path)))
    return 0


def cmd_hmac(args) -> int:
    key = _hex(args.key, "the key")
    print(hmac_sha256_hex(key, args.message.encode("utf-8")))
    return 0


def cmd_seal(args) -> int:
    key = _hex(args.key, "the key")
    nonce = _hex(args.nonce, "the nonce")
    ciphertext, tag = GCM(key).encrypt(nonce, _read(args.path))
    print("ciphertext %s" % ciphertext.hex())
    print("tag        %s" % tag.hex())
    return 0


def cmd_open(args) -> int:
    key = _hex(args.key, "the key")
    nonce = _hex(args.nonce, "the nonce")
    ciphertext = _hex(args.ciphertext, "the ciphertext")
    tag = _hex(args.tag, "the tag")
    try:
        plaintext = GCM(key).decrypt(nonce, ciphertext, tag)
    except InvalidTag as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 1
    if args.out:
        try:
            with open(args.out, "wb") as handle:
                handle.write(plaintext)
        except OSError as exc:
            print("could not write %s: %s" % (args.out, exc), file=sys.stderr)
            return 2
        print("plaintext  %d bytes written to %s" % (len(plaintext), args.out))
        return 0
    # Hex by default, so the output is text on a terminal. Ask for --out when
    # you want the raw bytes.
    print("plaintext  %s" % plaintext.hex())
    return 0


# The published vectors, so the arithmetic can be re-checked without pytest.
# Each row is (source, key, nonce, plaintext, aad, ciphertext, tag).
VECTORS = (
    (
        "SP 800-38D case 1",
        "00" * 16, "00" * 12, "", "", "",
        "58e2fccefa7e3061367f1d57a4e7455a",
    ),
    (
        "SP 800-38D case 2",
        "00" * 16, "00" * 12, "00" * 16, "",
        "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf",
    ),
    (
        "SP 800-38D case 3",
        "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", "",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        "4d5c2af327cd64a62cf35abd2ba6fab4",
    ),
    (
        "SP 800-38D case 4",
        "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        "5bc94fbc3221a5db94fae95ae7121a47",
    ),
)


def cmd_vectors(args) -> int:
    """Re-check the published GCM vectors and report each one."""

    failures = 0
    for name, key, nonce, plaintext, aad, ciphertext, tag in VECTORS:
        produced_ciphertext, produced_tag = GCM(
            _hex(key, "key")
        ).encrypt(_hex(nonce, "nonce"), _hex(plaintext, "plaintext"), _hex(aad, "aad"))
        ok = produced_ciphertext.hex() == ciphertext and produced_tag.hex() == tag
        failures += 0 if ok else 1
        print("%-20s %s" % (name, "ok" if ok else "MISMATCH"))
    print()
    print("%d of %d published vectors reproduced" % (len(VECTORS) - failures, len(VECTORS)))
    return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crypto-toolkit",
        description="The primitives in this project, over a command line.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    hashing = sub.add_parser("hash", help="SHA-256 of a file, or of standard input")
    hashing.add_argument("path", help="a file path, or - for standard input")
    hashing.set_defaults(func=cmd_hash)

    mac = sub.add_parser("hmac", help="HMAC-SHA256 of a message")
    mac.add_argument("key", help="the key, in hex")
    mac.add_argument("message", help="the message, as text")
    mac.set_defaults(func=cmd_hmac)

    seal = sub.add_parser("seal", help="AES-GCM encrypt a file, printing ciphertext and tag")
    seal.add_argument("key", help="the key, in hex (16, 24 or 32 bytes)")
    seal.add_argument("nonce", help="the nonce, in hex")
    seal.add_argument("path", help="a file path, or - for standard input")
    seal.set_defaults(func=cmd_seal)

    opening = sub.add_parser("open", help="AES-GCM decrypt, refusing a bad tag")
    opening.add_argument("key", help="the key, in hex")
    opening.add_argument("nonce", help="the nonce, in hex")
    opening.add_argument("ciphertext", help="the ciphertext, in hex")
    opening.add_argument("tag", help="the tag, in hex")
    opening.add_argument("--out", help="write the raw plaintext here instead of printing hex")
    opening.set_defaults(func=cmd_open)

    vectors = sub.add_parser("vectors", help="re-check the published GCM vectors")
    vectors.set_defaults(func=cmd_vectors)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        print("%s failed: %s" % (args.command, exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
