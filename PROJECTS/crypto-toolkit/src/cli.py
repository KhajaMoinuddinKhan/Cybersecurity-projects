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
import os
import sys

from .attacks.length_extension import forge_mac, naive_mac
from .attacks.nonce_reuse_ecdsa import recover_private_key
from .attacks.nonce_reuse_gcm import forge_tag, recover_hash_subkey
from .attacks.padding_oracle import padding_oracle, recover_plaintext
from .benchmark import format_report
from .benchmark import run as run_benchmark
from .cbc import CBC, pkcs7_unpad
from .ecdsa import P256_N, PrivateKey, generate_private_key, sign, verify
from .gcm import GCM, InvalidTag
from .hmac import hmac_sha256_hex
from .mlkem import MLKEM_512, MLKEM_768, MLKEM_1024
from .mlkem import decapsulate as mlkem_decapsulate
from .mlkem import encapsulate_random as mlkem_encapsulate
from .mlkem import generate_key_pair as mlkem_keygen
from .rsa import DecryptionError
from .rsa import decrypt as rsa_decrypt
from .rsa import encrypt as rsa_encrypt
from .rsa import generate_key_pair as rsa_keygen
from .sha256 import sha256, sha256_hex
from .web import DEFAULT_HOST, DEFAULT_PORT, serve


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


# --------------------------------------------------------------------------
# The attacks. Each one generates its own key, nonce and messages, mounts the
# attack against the real implementation, and reports whether what came out is
# what went in. Nothing here is a stored answer: the verification is always a
# comparison against the genuine implementation on values made up on the spot.
# --------------------------------------------------------------------------

def _demo_length_extension() -> bool:
    secret = os.urandom(24)
    message = b"user=guest&role=guest"
    appendage = b"&role=admin"

    tag = naive_mac(secret, message)
    forged_message, forged_mac = forge_mac(tag, len(secret), message, appendage)
    accepted = naive_mac(secret, forged_message) == forged_mac

    print("the attacker saw one message and its tag, and knows only that the secret is %d bytes"
          % len(secret))
    print("  original  %r" % message)
    print("  forged    %r" % forged_message)
    print("  the MAC function accepts the forged tag: %s" % accepted)
    return accepted


def _demo_gcm_nonce_reuse() -> bool:
    key = os.urandom(16)
    nonce = os.urandom(12)
    messages = []
    for index in range(3):
        ciphertext, tag = GCM(key).encrypt(nonce, os.urandom(16 + 8 * index))
        messages.append((tag, b"", ciphertext))

    subkey = recover_hash_subkey(messages)
    subkey_found = subkey == GCM(key).hash_subkey

    known_tag, known_aad, known_ciphertext = messages[0]
    chosen = b"transfer 999999 to mallory"
    chosen_ciphertext, chosen_tag = GCM(key).encrypt(nonce, chosen)
    forged = forge_tag(subkey, known_tag, known_aad, known_ciphertext, b"", chosen_ciphertext)
    accepted = forged == chosen_tag and GCM(key).decrypt(nonce, chosen_ciphertext, forged) == chosen

    print("three messages were encrypted under one nonce and the attacker has only the ciphertexts")
    print("  the hash subkey came out equal to the real one: %s" % subkey_found)
    print("  a tag forged for a message the attacker chose was accepted: %s" % accepted)
    return subkey_found and accepted


def _demo_padding_oracle() -> bool:
    key = os.urandom(16)
    iv = os.urandom(16)
    plaintext = b"the token is 9f3a41c7 and it never expires"
    ciphertext = CBC(key).encrypt(iv, plaintext)

    queries = []

    def oracle(preceding, block):
        queries.append(1)
        return padding_oracle(key)(preceding, block)

    recovered = recover_plaintext(oracle, iv, ciphertext)
    ok = pkcs7_unpad(recovered) == plaintext

    print("the attacker can ask only whether a ciphertext has valid padding, and gets yes or no")
    print("  the message: %r" % plaintext)
    print("  recovered  : %r" % pkcs7_unpad(recovered))
    print("  after %d yes-or-no questions" % len(queries))
    return ok


def _demo_ecdsa_nonce_reuse() -> bool:
    key = generate_private_key(os.urandom(32))
    nonce = int.from_bytes(os.urandom(32), "big") % (P256_N - 1) + 1
    digest1 = sha256(b"pay alice ten pounds")
    digest2 = sha256(b"pay alice a hundred pounds")
    signature1 = sign(key, digest1, nonce)
    signature2 = sign(key, digest2, nonce)

    recovered = recover_private_key(digest1, signature1, digest2, signature2)
    key_found = recovered == key.secret

    fresh = sha256(b"pay mallory everything")
    forged = sign(PrivateKey(recovered), fresh, int.from_bytes(os.urandom(32), "big") % (P256_N - 1) + 1)
    accepted = verify(key.public_key, fresh, forged)

    print("two signatures were published, and they share an r because the signer reused a nonce")
    print("  the private key was recovered and equals the real one: %s" % key_found)
    print("  a signature made with it verifies under the real public key: %s" % accepted)
    return key_found and accepted


DEMOS = {
    "length-extension": _demo_length_extension,
    "gcm-nonce-reuse": _demo_gcm_nonce_reuse,
    "padding-oracle": _demo_padding_oracle,
    "ecdsa-nonce-reuse": _demo_ecdsa_nonce_reuse,
}


def cmd_attack(args) -> int:
    """Run one attack, or all of them, against freshly generated values."""

    names = list(DEMOS) if args.which == "all" else [args.which]
    failures = 0
    for name in names:
        print("=" * 68)
        print(name)
        print("=" * 68)
        worked = DEMOS[name]()
        failures += 0 if worked else 1
        print("  --> %s" % ("the attack worked" if worked else "THE ATTACK FAILED"))
        print()
    print("%d of %d attacks worked" % (len(names) - failures, len(names)))
    return 1 if failures else 0


def cmd_serve(args) -> int:
    """Run the web console until interrupted."""

    serve(args.host, args.port)
    return 0


MLKEM_SETS = {"512": MLKEM_512, "768": MLKEM_768, "1024": MLKEM_1024}


def cmd_rsa(args) -> int:
    """Generate a key, encrypt a message, and open it again."""

    public, private = rsa_keygen(args.bits)
    message = args.message.encode()
    print("generated a %d-bit key" % args.bits)
    print("  the modulus is %d bytes" % public.size_bytes())
    try:
        ciphertext = rsa_encrypt(public, message)
    except ValueError as exc:
        print("  %s" % exc)
        return 2
    print("  %d bytes of message became %d bytes of ciphertext" % (len(message), len(ciphertext)))
    print("  the message came back: %s" % (rsa_decrypt(private, ciphertext) == message))

    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0x01
    try:
        rsa_decrypt(private, bytes(tampered))
    except DecryptionError:
        print("  a ciphertext with one bit flipped was refused")
    else:
        print("  A TAMPERED CIPHERTEXT WAS ACCEPTED -- that is a bug")
        return 1
    return 0


def cmd_mlkem(args) -> int:
    """Generate a key pair, encapsulate a secret, and recover it."""

    parameters = MLKEM_SETS[args.parameter_set]
    public, private = mlkem_keygen(parameters)
    print("%s, security category %d" % (parameters.name, parameters.security_category))
    print("  encapsulation key %d bytes, decapsulation key %d bytes"
          % (len(public), len(private)))

    sender_secret, ciphertext = mlkem_encapsulate(public, parameters)
    print("  %d bytes of ciphertext carry a %d-byte shared secret"
          % (len(ciphertext), len(sender_secret)))
    receiver_secret = mlkem_decapsulate(private, ciphertext, parameters)
    print("  the two sides agree: %s" % (sender_secret == receiver_secret))

    tampered = bytearray(ciphertext)
    tampered[len(ciphertext) // 2] ^= 0x01
    rejected = mlkem_decapsulate(private, bytes(tampered), parameters)
    print("  a ciphertext with one bit flipped was rejected implicitly: %s"
          % (rejected != sender_secret))
    print("  it returned a secret rather than an error, which is the design: a")
    print("  decapsulation that raised would answer whether the ciphertext was well formed")
    return 0


def cmd_benchmark(args) -> int:
    """Measure RSA against ML-KEM on size, speed and quoted security strength."""

    result = run_benchmark(
        rsa_bits=tuple(args.rsa_bits),
        include_toy=args.include_toy,
        keygen_iterations=args.keygen_iterations,
        mlkem_keygen_iterations=args.keygen_iterations,
        operation_iterations=args.iterations,
    )
    print(format_report(result))
    return 0


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

    serving = sub.add_parser("serve", help="run the local web console over the toolkit and the attacks")
    serving.add_argument("--host", default=DEFAULT_HOST,
                         help="the address to bind; the loopback address unless you insist")
    serving.add_argument("--port", type=int, default=DEFAULT_PORT, help="the port to listen on")
    serving.set_defaults(func=cmd_serve)

    attack = sub.add_parser("attack", help="mount one of the attacks against fresh values")
    attack.add_argument("which", choices=sorted(DEMOS) + ["all"],
                        help="which attack to run, or all of them")
    attack.set_defaults(func=cmd_attack)

    rsa_verb = sub.add_parser("rsa", help="generate an RSA key and open a message with it")
    rsa_verb.add_argument("message", nargs="?", default="a message to protect",
                          help="the message to encrypt and decrypt again")
    rsa_verb.add_argument("--bits", type=int, default=2048, help="the modulus size")
    rsa_verb.set_defaults(func=cmd_rsa)

    kem = sub.add_parser("mlkem", help="generate an ML-KEM key pair and establish a secret")
    kem.add_argument("--parameter-set", dest="parameter_set", default="768",
                     choices=sorted(MLKEM_SETS), help="which FIPS 203 parameter set")
    kem.set_defaults(func=cmd_mlkem)

    bench = sub.add_parser("benchmark", help="measure RSA against ML-KEM")
    bench.add_argument("--rsa-bits", dest="rsa_bits", type=int, nargs="+", default=[2048, 3072],
                       help="which RSA key sizes to measure")
    bench.add_argument("--iterations", type=int, default=20,
                       help="how many operations to time for encryption and decapsulation")
    bench.add_argument("--keygen-iterations", dest="keygen_iterations", type=int, default=1,
                       help="how many key generations to time; one is slow enough already")
    bench.add_argument("--include-toy", dest="include_toy", action="store_true",
                       help="also measure the reduced parameter set, which is not a standard one")
    bench.set_defaults(func=cmd_benchmark)

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
