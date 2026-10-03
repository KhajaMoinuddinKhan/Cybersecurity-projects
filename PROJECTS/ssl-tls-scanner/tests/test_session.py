"""The main handshake verifies first and only disables verification to inspect."""
from __future__ import annotations

import ssl

import pytest

from src import scanner

def test_main_handshake_prefers_a_verified_connection(monkeypatch):
    verified = ([b"leaf"], "TLSv1.3", "TLS_AES_256_GCM_SHA384")
    sentinel = object()

    def fake_handshake(host, port, timeout, context):
        assert context is sentinel
        return verified

    monkeypatch.setattr(scanner.ssl, "create_default_context", lambda: sentinel)
    monkeypatch.setattr(scanner, "_handshake", fake_handshake)
    chain, version, cipher, chain_valid, error = scanner._main_handshake("example.test", 443, 5.0)
    assert chain_valid is True
    assert error is None
    assert version == "TLSv1.3"
    assert chain == [b"leaf"]

def test_main_handshake_falls_back_to_an_unverified_read(monkeypatch):
    unverified = ([b"leaf"], "TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384")
    verified_context = object()
    unverified_context = object()

    def fake_handshake(host, port, timeout, context):
        if context is verified_context:
            raise ssl.SSLCertVerificationError("self-signed certificate")
        assert context is unverified_context
        return unverified

    monkeypatch.setattr(scanner.ssl, "create_default_context", lambda: verified_context)
    monkeypatch.setattr(scanner, "_unverified_context", lambda: unverified_context)
    monkeypatch.setattr(scanner, "_handshake", fake_handshake)
    chain, version, cipher, chain_valid, error = scanner._main_handshake("example.test", 443, 5.0)
    assert chain_valid is False
    assert "self-signed" in error
    assert version == "TLSv1.2"

def test_scan_refuses_to_report_without_a_certificate(monkeypatch):
    monkeypatch.setattr(scanner, "_main_handshake", lambda host, port, timeout: ([], "TLSv1.3", "cipher", True, None))
    with pytest.raises(ssl.SSLError):
        scanner.scan("example.test")
