"""The local web console: the page, the API behind it, and the rule it must not break.

The page tests are the same contract the other console in this repository holds
itself to -- no stylesheet, font or script fetched from anywhere -- because a
project that argues about nonce reuse has no business telling a font server when
it is open, and the page has to render on a machine with no network.

The API tests drive a real server on an ephemeral port rather than calling the
handler functions directly, so what is exercised is the thing that actually
listens. The attacks are asserted the same way the rest of this project asserts
them: by checking the recovery against the genuine implementation, never against
a stored value.
"""

import ast
import json
import os
import socket
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

from src import web  # noqa: E402

PAGE = (PROJECT / "src" / "templates" / "console.html").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The page itself
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("token", [
    "http://", "https://", "<link", "<script src", "@import", "//cdn", "integrity=",
])
def test_the_page_fetches_nothing_from_anywhere(token):
    """Self-contained means self-contained: no origin other than this server."""

    assert token not in PAGE


def test_the_page_is_one_file_with_its_style_and_script_inline():
    assert PAGE.count("<style>") == 1
    assert PAGE.count("<script>") == 1
    assert "<script src" not in PAGE
    assert PAGE.lstrip().startswith("<!DOCTYPE html>")


def test_the_page_asks_only_this_server_for_data():
    """Every request is a relative path, so the page works with no network at all."""

    assert "/api/attack/" in PAGE
    assert "fetch(\"/api/" in PAGE or "fetch('/api/" in PAGE


def test_the_console_binds_to_the_loopback_address_by_default():
    """It takes a key from whoever opens it, so the default must not be reachable."""

    assert web.DEFAULT_HOST == "127.0.0.1"


def test_the_project_still_imports_nothing_outside_the_standard_library():
    """The rule the whole project rests on, checked by reading the source.

    A web console is the obvious way to break this by accident, so the rule is
    asserted here as well as in the README. The ast walk means it cannot be
    satisfied by a comment claiming it.
    """

    standard = set(sys.stdlib_module_names)
    offenders = {}
    for path in sorted((PROJECT / "src").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    found.add(node.module.split(".")[0])
        outside = sorted(name for name in found if name not in standard)
        if outside:
            offenders[str(path.relative_to(PROJECT))] = outside
    assert offenders == {}, offenders


# ---------------------------------------------------------------------------
# The API, over a real socket
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def server():
    """A real server on an ephemeral port, so nothing here assumes a fixed one."""

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    try:
        yield "http://%s:%d" % (host, port)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def call(base, path, method="GET", payload=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    request = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_the_page_is_served(server):
    status, body = call(server, "/")
    assert status == 200
    text = body.decode("utf-8")
    assert "Cryptographic toolkit" in text
    assert "http://" not in text and "https://" not in text


def test_the_published_vectors_reproduce_over_the_api(server):
    status, body = call(server, "/api/vectors")
    payload = json.loads(body)
    assert status == 200
    assert payload["all_match"] is True
    assert all(row["ciphertext_matches"] and row["tag_matches"] for row in payload["gcm"])
    assert all(row["matches"] for row in payload["digests"])


def test_the_hash_endpoint_agrees_with_the_published_digest(server):
    status, body = call(server, "/api/hash", "POST", {"data": "abc"})
    assert status == 200
    assert json.loads(body)["sha256"] == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_the_hmac_endpoint_agrees_with_the_rfc_vector(server):
    status, body = call(server, "/api/hmac", "POST",
                        {"key": "Jefe", "message": "what do ya want for nothing?"})
    assert status == 200
    assert json.loads(body)["hmac"] == (
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )


def test_sealing_and_opening_round_trips_over_the_api(server):
    key, nonce = "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888"
    plaintext = "a message that has to survive the trip"

    status, body = call(server, "/api/gcm/seal", "POST",
                        {"key": key, "nonce": nonce, "plaintext": plaintext, "aad": ""})
    assert status == 200
    sealed = json.loads(body)

    status, body = call(server, "/api/gcm/open", "POST",
                        {"key": key, "nonce": nonce, "ciphertext": sealed["ciphertext"],
                         "tag": sealed["tag"], "aad": ""})
    assert status == 200
    assert json.loads(body)["plaintext"] == plaintext


def test_a_tampered_tag_is_refused_over_the_api(server):
    key, nonce = "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888"
    status, body = call(server, "/api/gcm/seal", "POST",
                        {"key": key, "nonce": nonce, "plaintext": "secret", "aad": ""})
    sealed = json.loads(body)
    flipped = ("0" if sealed["tag"][0] != "0" else "1") + sealed["tag"][1:]

    status, body = call(server, "/api/gcm/open", "POST",
                        {"key": key, "nonce": nonce, "ciphertext": sealed["ciphertext"],
                         "tag": flipped, "aad": ""})
    assert status == 200
    answer = json.loads(body)
    assert answer["refused"] is True
    assert "plaintext" not in answer


@pytest.mark.parametrize("name", ["length-extension", "gcm-nonce-reuse",
                                  "padding-oracle", "ecdsa-nonce-reuse"])
def test_each_attack_works_over_the_api(server, name):
    """The headline: the page's buttons really mount the attacks.

    ``worked`` is only true when the result was checked against the genuine
    implementation inside the endpoint, so this asserts the attack rather than
    the shape of the response.
    """

    status, body = call(server, "/api/attack/" + name)
    payload = json.loads(body)
    assert status == 200
    assert payload["worked"] is True, payload


def test_the_attacks_report_their_own_evidence(server):
    status, body = call(server, "/api/attack/gcm-nonce-reuse")
    payload = json.loads(body)
    assert payload["subkey_recovered"] is True
    assert payload["accepted_by_gcm"] is True
    assert payload["recovered_subkey"] == payload["real_subkey"]

    status, body = call(server, "/api/attack/ecdsa-nonce-reuse")
    payload = json.loads(body)
    assert payload["key_recovered"] is True
    assert payload["signature_verified"] is True
    assert payload["recovered_key"] == payload["real_key"]


def test_the_length_extension_attack_shows_hmac_resisting(server):
    status, body = call(server, "/api/attack/length-extension")
    payload = json.loads(body)
    assert payload["accepted_by_the_mac"] is True
    assert payload["hmac_resists"] is True


def test_the_padding_oracle_reports_its_query_count(server):
    status, body = call(server, "/api/attack/padding-oracle")
    payload = json.loads(body)
    assert payload["recovered_matches"] is True
    assert payload["queries"] > 100


def test_bad_input_is_refused_with_a_reason(server):
    status, body = call(server, "/api/hash", "POST", {"data": 12})
    assert status == 400
    assert "error" in json.loads(body)

    status, body = call(server, "/api/gcm/seal", "POST",
                        {"key": "not hex", "nonce": "00" * 12, "plaintext": "x"})
    assert status == 400

    status, body = call(server, "/api/gcm/open", "POST",
                        {"key": "00" * 16, "nonce": "00" * 12,
                         "ciphertext": "00" * 16, "tag": "00" * 16})
    assert status == 200
    assert json.loads(body)["refused"] is True


def test_an_unknown_route_is_a_404(server):
    assert call(server, "/api/attack/nope")[0] == 404
    assert call(server, "/api/nothing")[0] == 404
    status, body = call(server, "/api/attack/nope")
    assert "known" in json.loads(body)


def test_a_malformed_body_is_refused(server):
    request = urllib.request.Request(server + "/api/hash", data=b"not json",
                                     method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    assert status == 400
