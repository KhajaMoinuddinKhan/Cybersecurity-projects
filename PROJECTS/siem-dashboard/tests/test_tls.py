"""HTTPS is opt-in, and a half-configured or unusable pair must fail loudly."""
import shutil
import subprocess

import pytest

from src.app import tls_context


def test_no_certificate_means_plain_http():
    assert tls_context(None, None) is None


def test_a_half_configured_pair_is_refused(tmp_path):
    with pytest.raises(ValueError, match="both --tls-cert and --tls-key"):
        tls_context(tmp_path / "server.crt", None)
    with pytest.raises(ValueError, match="both --tls-cert and --tls-key"):
        tls_context(None, tmp_path / "server.key")


def test_a_missing_file_is_named(tmp_path):
    with pytest.raises(ValueError, match="TLS certificate not found"):
        tls_context(tmp_path / "absent.crt", tmp_path / "absent.key")


def test_a_key_that_is_not_a_key_is_refused(tmp_path):
    """A file that exists but is not a usable key must not start a server."""

    if shutil.which("openssl") is None or "'" in str(tmp_path):
        pytest.skip("needs openssl and a path it can write into")
    certificate = tmp_path / "server.crt"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-keyout", str(tmp_path / "server.key"),
            "-out", str(certificate),
        ],
        capture_output=True, check=True, timeout=180,
    )
    rubbish = tmp_path / "not-a-key.pem"
    rubbish.write_text("this is not a key\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Could not load the TLS certificate and key"):
        tls_context(certificate, rubbish)


def test_a_real_pair_is_accepted(tmp_path):
    if shutil.which("openssl") is None or "'" in str(tmp_path):
        pytest.skip("needs openssl and a path it can write into")
    certificate = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(certificate),
        ],
        capture_output=True, check=True, timeout=180,
    )
    context = tls_context(certificate, key)
    assert context == (str(certificate), str(key))
