"""A local web console over the primitives and the four attacks.

The toolkit is a library and a command line, and both are fine for someone who
already knows what they want to type. This is for the other case: seeing the
attacks run, changing an input, and watching what changes. It is a small
standard-library HTTP server and one self-contained page.

It is standard library on purpose. The rule this project holds itself to is that
nothing under ``src/`` imports a third-party package, and that rule is checked
by walking the source with the ast module rather than by trusting anyone. A web
console built on a framework would break it, so the server here is
``http.server`` and the page is served as one file with no build step.

Two things it deliberately is not. It is not a service: it binds to the loopback
address and refuses to bind anywhere else unless asked, because it will happily
encrypt whatever you paste into it with whatever key you paste in, and that is
not something to expose. And it is not a second implementation of anything --
every button calls the same functions the command line calls, so a result on the
page is a result from the library rather than a parallel copy of it.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .attacks.length_extension import forge_mac, naive_mac
from .attacks.nonce_reuse_ecdsa import recover_private_key
from .attacks.nonce_reuse_gcm import forge_tag, recover_hash_subkey
from .attacks.padding_oracle import padding_oracle, recover_plaintext
from .cbc import CBC, PaddingError, pkcs7_unpad
from .ecdsa import P256_N, PrivateKey, generate_private_key, sign, verify
from .gcm import GCM, InvalidTag
from .hmac import hmac_sha256, hmac_sha256_hex
from .benchmark import run as benchmark_run
from .mlkem import MLKEM_768
from .mlkem import decapsulate as mlkem_decapsulate
from .mlkem import encapsulate_random as mlkem_encapsulate
from .mlkem import generate_key_pair as mlkem_keygen
from .rsa import DecryptionError
from .rsa import decrypt as rsa_decrypt
from .rsa import encrypt as rsa_encrypt
from .rsa import generate_key_pair as rsa_keygen
from .sha256 import sha256, sha256_hex

TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "console.html"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8088
MAX_BODY = 1 << 20


# --------------------------------------------------------------------------
# The four attacks, each run against values generated at the moment it is asked
# for and each reporting whether what came out is what went in. Nothing here is
# a stored answer, which is the same promise the test suite makes.
# --------------------------------------------------------------------------

def run_length_extension() -> dict:
    secret = os.urandom(24)
    # The session id is fresh, so the message a run reports back cannot be a
    # canned one -- and the reader can see that it changed since last time.
    message = b"user=guest&role=guest&session=" + os.urandom(4).hex().encode()
    appendage = b"&role=admin"

    known_mac = naive_mac(secret, message)
    forged_message, forged_mac = forge_mac(known_mac, len(secret), message, appendage)
    accepted = naive_mac(secret, forged_message) == forged_mac
    # The same extension against HMAC, which is the point of the attack.
    hmac_tag = hmac_sha256(secret, forged_message)
    return {
        "worked": accepted,
        "secret_length": len(secret),
        "original": message.decode("latin-1"),
        "forged": forged_message.decode("latin-1"),
        "forged_mac": forged_mac.hex(),
        "accepted_by_the_mac": accepted,
        "the_same_forgery_against_hmac": hmac_tag.hex(),
        "hmac_resists": hmac_tag != forged_mac,
    }


def run_gcm_nonce_reuse() -> dict:
    key = os.urandom(16)
    nonce = os.urandom(12)
    messages = []
    for index in range(3):
        ciphertext, tag = GCM(key).encrypt(nonce, os.urandom(16 + 8 * index))
        messages.append((tag, b"", ciphertext))

    subkey = recover_hash_subkey(messages)
    subkey_found = subkey == GCM(key).hash_subkey

    known_tag, known_aad, known_ciphertext = messages[0]
    chosen = b"transfer %d to mallory" % int.from_bytes(os.urandom(2), "big")
    chosen_ciphertext, chosen_tag = GCM(key).encrypt(nonce, chosen)
    forged = forge_tag(subkey, known_tag, known_aad, known_ciphertext, b"", chosen_ciphertext)
    accepted = forged == chosen_tag and GCM(key).decrypt(nonce, chosen_ciphertext, forged) == chosen
    return {
        "worked": subkey_found and accepted,
        "messages": len(messages),
        "recovered_subkey": subkey.hex(),
        "real_subkey": GCM(key).hash_subkey.hex(),
        "subkey_recovered": subkey_found,
        "chosen_message": chosen.decode("latin-1"),
        "forged_tag": forged.hex(),
        "accepted_by_gcm": accepted,
    }


def run_padding_oracle() -> dict:
    key = os.urandom(16)
    iv = os.urandom(16)
    # A readable sentence with a token nobody could have known: if the attack
    # recovers this, it recovered it rather than recalled it.
    plaintext = b"the token is " + os.urandom(8).hex().encode() + b" and it never expires"
    ciphertext = CBC(key).encrypt(iv, plaintext)

    queries = []

    def oracle(preceding, block):
        queries.append(1)
        return padding_oracle(key)(preceding, block)

    recovered = recover_plaintext(oracle, iv, ciphertext)
    stripped = pkcs7_unpad(recovered)
    return {
        "worked": stripped == plaintext,
        "message": plaintext.decode("latin-1"),
        "recovered": stripped.decode("latin-1"),
        "queries": len(queries),
        "recovered_matches": stripped == plaintext,
    }


def run_ecdsa_nonce_reuse() -> dict:
    key = generate_private_key(os.urandom(32))
    nonce = int.from_bytes(os.urandom(32), "big") % (P256_N - 1) + 1
    digest1 = sha256(b"pay alice %d pounds" % int.from_bytes(os.urandom(2), "big"))
    digest2 = sha256(b"pay alice %d pounds" % int.from_bytes(os.urandom(2), "big"))
    signature1 = sign(key, digest1, nonce)
    signature2 = sign(key, digest2, nonce)

    recovered = recover_private_key(digest1, signature1, digest2, signature2)
    key_found = recovered == key.secret

    fresh = sha256(b"pay mallory " + os.urandom(4).hex().encode())
    forged = sign(PrivateKey(recovered), fresh, int.from_bytes(os.urandom(32), "big") % (P256_N - 1) + 1)
    accepted = verify(key.public_key, fresh, forged)
    return {
        "worked": key_found and accepted,
        "shared_r": hex(signature1[0])[:22] + "...",
        "recovered_key": hex(recovered),
        "real_key": hex(key.secret),
        "key_recovered": key_found,
        "signature_verified": accepted,
    }


ATTACKS = {
    "length-extension": run_length_extension,
    "gcm-nonce-reuse": run_gcm_nonce_reuse,
    "padding-oracle": run_padding_oracle,
    "ecdsa-nonce-reuse": run_ecdsa_nonce_reuse,
}


# --------------------------------------------------------------------------
# The primitives, over the same functions the command line uses.
# --------------------------------------------------------------------------

def run_mlkem() -> dict:
    """A key pair, an encapsulation, and the two sides agreeing.

    ML-KEM is here rather than in a separate view because it is a primitive and
    the point of this page is that the primitives are reachable. The interesting
    line is the last one: a tampered ciphertext is refused by returning a
    different secret, not by raising, and that is a design decision rather than
    an arithmetic one -- a decapsulation that raised would answer the question
    "was this ciphertext well formed".
    """
    parameters = MLKEM_768
    encapsulation_key, decapsulation_key = mlkem_keygen(parameters)
    sender_secret, ciphertext = mlkem_encapsulate(encapsulation_key, parameters)
    receiver_secret = mlkem_decapsulate(decapsulation_key, ciphertext, parameters)

    tampered = bytearray(ciphertext)
    tampered[len(ciphertext) // 2] ^= 0x01
    rejected = mlkem_decapsulate(decapsulation_key, bytes(tampered), parameters)

    return {
        "worked": sender_secret == receiver_secret and rejected != sender_secret,
        "parameter_set": parameters.name,
        "security_category": parameters.security_category,
        "encapsulation_key_bytes": len(encapsulation_key),
        "decapsulation_key_bytes": len(decapsulation_key),
        "ciphertext_bytes": len(ciphertext),
        "shared_secret_bytes": len(sender_secret),
        "shared_secret": sender_secret.hex(),
        "sender_and_receiver_agree": sender_secret == receiver_secret,
        "tampered_ciphertext_rejected_implicitly": rejected != sender_secret,
        "rejection_returned_a_secret_not_an_error": len(rejected) == 32,
    }


def run_rsa(message: str) -> dict:
    """Generate a key, seal a message, open it again, and refuse a tampered one.

    The whole exchange happens here rather than being split across requests, so
    the page never has to hold a private key. That also means the key is fresh
    every time the button is pressed, which is the property a reader cannot
    check for themselves if the page shows a stored result.
    """
    public, private = rsa_keygen(2048)
    payload = message.encode("utf-8")
    ciphertext = rsa_encrypt(public, payload)
    recovered = rsa_decrypt(private, ciphertext)

    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0x01
    try:
        rsa_decrypt(private, bytes(tampered))
        refused = False
    except DecryptionError:
        refused = True

    return {
        "worked": recovered == payload and refused,
        "modulus_bytes": public.size_bytes(),
        "message_bytes": len(payload),
        "ciphertext_bytes": len(ciphertext),
        "message_recovered": recovered == payload,
        "tampered_ciphertext_refused": refused,
        "ciphertext": ciphertext.hex(),
        "message": message,
    }


def run_quick_benchmark() -> dict:
    """A reduced measurement, sized for a button press rather than a terminal.

    RSA-3072 key generation takes seconds, and the page should answer while
    somebody is still looking at it, so this measures one 2048-bit key and three
    operations per scheme. The command line runs the full comparison. The result
    says which one this is, because a page showing numbers without saying how
    they were produced is the easiest thing here to misread.
    """
    result = benchmark_run(rsa_bits=(2048,), include_toy=False,
                           keygen_iterations=1, mlkem_keygen_iterations=1,
                           operation_iterations=3)
    result["quick"] = True
    result["notes"] = [
        "This is the quick measurement: one 2048-bit RSA key and three operations "
        "per scheme, so the page answers while you are still looking at it. "
        "`python -m src.cli benchmark` runs the full comparison including RSA-3072.",
    ] + result["notes"]
    return result


def published_vectors() -> dict:
    """Re-check the published GCM examples and the FIPS and RFC digests."""

    cases = [
        ("SP 800-38D case 1", "00" * 16, "00" * 12, "", "",
         "", "58e2fccefa7e3061367f1d57a4e7455a"),
        ("SP 800-38D case 2", "00" * 16, "00" * 12, "00" * 16, "",
         "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"),
        ("SP 800-38D case 3", "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
         "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", "",
         "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
         "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
         "4d5c2af327cd64a62cf35abd2ba6fab4"),
        ("SP 800-38D case 4", "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
         "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
         "feedfacedeadbeeffeedfacedeadbeefabaddad2",
         "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
         "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
         "5bc94fbc3221a5db94fae95ae7121a47"),
    ]
    rows = []
    for name, key, nonce, plaintext, aad, ciphertext, tag in cases:
        produced_ciphertext, produced_tag = GCM(bytes.fromhex(key)).encrypt(
            bytes.fromhex(nonce), bytes.fromhex(plaintext), bytes.fromhex(aad))
        rows.append({
            "name": name,
            "ciphertext_matches": produced_ciphertext.hex() == ciphertext,
            "tag_matches": produced_tag.hex() == tag,
        })
    digests = [
        ("FIPS 180-4, the empty string",
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", b""),
        ("FIPS 180-4, abc",
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", b"abc"),
        ("RFC 4231 case 2, HMAC of a known message",
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", None),
    ]
    digest_rows = []
    for name, expected, data in digests:
        if data is None:
            produced = hmac_sha256_hex(bytes.fromhex("4a656665"), b"what do ya want for nothing?")
        else:
            produced = sha256_hex(data)
        digest_rows.append({"name": name, "matches": produced == expected, "digest": produced})
    return {
        "gcm": rows,
        "digests": digest_rows,
        "all_match": all(r["ciphertext_matches"] and r["tag_matches"] for r in rows)
                     and all(r["matches"] for r in digest_rows),
    }


def _hex(value, field):
    if not isinstance(value, str):
        raise ValueError("%s must be a hex string" % field)
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("%s is not valid hex: %s" % (field, exc)) from exc


def api_rsa(payload: dict) -> dict:
    message = payload.get("message")
    if not isinstance(message, str):
        raise ValueError("message must be a string")
    return run_rsa(message)


def api_hash(payload: dict) -> dict:
    data = payload.get("data", "")
    if not isinstance(data, str):
        raise ValueError("data must be a string")
    return {"sha256": sha256_hex(data.encode("utf-8"))}


def api_hmac(payload: dict) -> dict:
    key = payload.get("key", "")
    message = payload.get("message", "")
    if not isinstance(key, str) or not isinstance(message, str):
        raise ValueError("the key and the message must be strings")
    return {"hmac": hmac_sha256_hex(key.encode("utf-8"), message.encode("utf-8"))}


def api_seal(payload: dict) -> dict:
    key = _hex(payload.get("key", ""), "the key")
    nonce = _hex(payload.get("nonce", ""), "the nonce")
    plaintext = payload.get("plaintext", "")
    aad = payload.get("aad", "")
    if not isinstance(plaintext, str) or not isinstance(aad, str):
        raise ValueError("the plaintext and the associated data must be strings")
    ciphertext, tag = GCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad.encode("utf-8"))
    return {"ciphertext": ciphertext.hex(), "tag": tag.hex()}


def api_open(payload: dict) -> dict:
    key = _hex(payload.get("key", ""), "the key")
    nonce = _hex(payload.get("nonce", ""), "the nonce")
    ciphertext = _hex(payload.get("ciphertext", ""), "the ciphertext")
    tag = _hex(payload.get("tag", ""), "the tag")
    aad = payload.get("aad", "")
    if not isinstance(aad, str):
        raise ValueError("the associated data must be a string")
    try:
        plaintext = GCM(key).decrypt(nonce, ciphertext, tag, aad.encode("utf-8"))
    except InvalidTag:
        return {"refused": True, "reason": "the tag does not match this ciphertext"}
    return {"refused": False, "plaintext": plaintext.decode("utf-8", "replace")}


POST_ROUTES = {
    "/api/hash": api_hash,
    "/api/hmac": api_hmac,
    "/api/gcm/seal": api_seal,
    "/api/gcm/open": api_open,
    "/api/rsa": api_rsa,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "crypto-toolkit"

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload, indent=2).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ValueError("the request body is too large")
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("the request body is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("the request body must be an object")
        return payload

    def do_GET(self) -> None:  # noqa: N802 - the name is fixed by the base class
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            try:
                body = TEMPLATE_PATH.read_bytes()
            except OSError:
                self._json(500, {"error": "the console page is missing from the package"})
                return
            self._send(200, body, "text/html; charset=utf-8")
            return
        if path == "/api/mlkem":
            self._json(200, run_mlkem())
        if path == "/api/benchmark":
            self._json(200, run_quick_benchmark())
        if path == "/api/vectors":
            self._json(200, published_vectors())
            return
        if path.startswith("/api/attack/"):
            name = path[len("/api/attack/"):]
            runner = ATTACKS.get(name)
            if runner is None:
                self._json(404, {"error": "no such attack", "known": sorted(ATTACKS)})
                return
            try:
                self._json(200, runner())
            except Exception as exc:  # a failed attack is a result, not a crash
                self._json(200, {"worked": False, "error": str(exc)})
            return
        self._json(404, {"error": "not found"})

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        handler = POST_ROUTES.get(path)
        if handler is None:
            self._json(404, {"error": "not found"})
            return
        try:
            payload = self._read_json()
            self._json(200, handler(payload))
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:  # never take the server down for one bad request
            self._json(500, {"error": str(exc)})

    def log_message(self, fmt, *args) -> None:
        """Keep the console quiet unless the caller asked for noise."""

        if os.environ.get("CRYPTO_TOOLKIT_WEB_VERBOSE"):
            super().log_message(fmt, *args)


def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, *, quiet: bool = False) -> None:
    """Run the console until interrupted.

    The host is the loopback address by default. Binding it anywhere else is
    possible and is almost always a mistake: the page takes a key and a
    plaintext from whoever opens it and will encrypt with them.
    """

    server = ThreadingHTTPServer((host, port), Handler)
    actual_host, actual_port = server.server_address[0], server.server_address[1]
    if not quiet:
        print("crypto-toolkit console on port %d, serving %s" % (actual_port, TEMPLATE_PATH.name))
        print("bound to %s -- it takes a key from whoever opens it, so keep it on this machine"
              % actual_host)
        print("press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if not quiet:
            print("\nconsole stopped")
