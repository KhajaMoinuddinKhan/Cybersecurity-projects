import ssl
from src import scanner


def test_scan_preserves_hostname_and_verified_context(monkeypatch):
    calls = []
    class Socket:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def getpeercert(self): return {"notAfter": "Jan 02 03:04:05 2030 GMT"}
        def cipher(self): return ("TEST-CIPHER", "TLSv1.3", 256)
        def version(self): return "TLSv1.3"
    raw = Socket()
    class Context:
        def wrap_socket(self, sock, server_hostname):
            assert sock is raw
            calls.append(server_hostname)
            return Socket()
    monkeypatch.setattr(scanner.socket, "create_connection", lambda address, timeout: raw)
    monkeypatch.setattr(scanner.ssl, "create_default_context", lambda: Context())
    result = scanner.scan("example.test")
    assert calls == ["example.test"]
    assert result["tls_version"] == "TLSv1.3"
    assert result["certificate_expires"] == "2030-01-02T03:04:05+00:00"


def test_certificate_failure_is_not_silently_ignored(monkeypatch):
    import pytest
    class Raw:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    class Context:
        def wrap_socket(self, *args, **kwargs):
            raise ssl.SSLCertVerificationError("untrusted certificate")
    monkeypatch.setattr(scanner.socket, "create_connection", lambda *args, **kwargs: Raw())
    monkeypatch.setattr(scanner.ssl, "create_default_context", lambda: Context())
    with pytest.raises(ssl.SSLCertVerificationError):
        scanner.scan("example.test")
