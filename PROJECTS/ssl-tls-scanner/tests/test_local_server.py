"""End-to-end checks against a local self-signed TLS server (no internet needed)."""
from __future__ import annotations

import socket

import pytest

from src import scanner

def test_scan_reads_a_self_signed_certificate(self_signed_server):
    result = scanner.scan(self_signed_server.host, self_signed_server.port, timeout=5.0)
    assert result["tls_version"] in ("TLSv1.2", "TLSv1.3")
    assert result["cipher"]
    assert len(result["certificate_chain"]) == 1
    assert result["self_signed"] is True
    assert result["chain_valid"] is False
    assert result["hostname_matches"] is True  # 127.0.0.1 is in the certificate SANs
    assert result["certificate"]["key_type"] == "RSA"
    assert result["certificate"]["key_size"] == 2048
    assert result["forward_secrecy"] is True
    assert any("self-signed" in reason for reason in result["grade"]["reasons"])

def test_scan_enumerates_protocol_versions(self_signed_server):
    protocols = scanner.scan(self_signed_server.host, self_signed_server.port, timeout=5.0)["protocols"]
    assert protocols["TLSv1.0"]["probe_performed"] is True
    assert protocols["TLSv1.0"]["deprecated"] is True
    assert protocols["TLSv1.0"]["accepted"] is False
    assert protocols["TLSv1.1"]["accepted"] is False
    assert protocols["TLSv1.2"]["accepted"] is True
    assert protocols["TLSv1.3"]["accepted"] is True

def test_scan_reports_the_hsts_header(self_signed_server):
    hsts = scanner.scan(self_signed_server.host, self_signed_server.port, timeout=5.0)["hsts"]
    assert hsts["checked"] is True
    assert hsts["present"] is True
    assert hsts["max_age"] == 31536000
    assert hsts["include_subdomains"] is True

def test_scan_reports_a_missing_hsts_header(plain_server):
    result = scanner.scan(plain_server.host, plain_server.port, timeout=5.0)
    assert result["hsts"]["checked"] is True
    assert result["hsts"]["present"] is False
    assert any("Strict-Transport-Security" in reason for reason in result["grade"]["reasons"])

def test_scan_walks_the_full_chain(chain_server):
    result = scanner.scan(chain_server.host, chain_server.port, timeout=5.0)
    assert len(result["certificate_chain"]) == 2
    assert result["self_signed"] is False
    assert result["certificate_issuer"].startswith("commonName=Hermes Test CA")
    assert result["certificate_chain"][1]["self_signed"] is True  # the test CA is self-signed

def test_scan_raises_when_nothing_is_listening():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    with pytest.raises((OSError, scanner.ssl.SSLError)):
        scanner.scan("127.0.0.1", port, timeout=2.0)
