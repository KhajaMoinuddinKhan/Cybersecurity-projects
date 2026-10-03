"""Shared fixtures: a small self-signed TLS server that runs on 127.0.0.1."""
from __future__ import annotations

import os
import socket
import ssl
import threading

import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

class LocalTlsServer:
    """A one-line HTTP server behind TLS, used instead of reaching the internet."""

    def __init__(self, certfile: str, keyfile: str, hsts: str | None = None) -> None:
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(certfile, keyfile)
        self._context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._hsts = hsts
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(16)
        self.host = "127.0.0.1"
        self.port = self._socket.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except OSError:
                break
            try:
                with self._context.wrap_socket(connection, server_side=True) as tls:
                    try:
                        tls.recv(4096)
                        headers = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n"
                        if self._hsts:
                            headers += f"Strict-Transport-Security: {self._hsts}\r\n"
                        tls.sendall(headers.encode("ascii") + b"\r\n\r\nok")
                    except OSError:
                        pass
            except (ssl.SSLError, OSError):
                pass

    def stop(self) -> None:
        self._stop.set()
        try:
            with socket.create_connection((self.host, self.port), timeout=1):
                pass
        except OSError:
            pass
        try:
            self._socket.close()
        except OSError:
            pass

@pytest.fixture
def self_signed_server():
    server = LocalTlsServer(
        os.path.join(FIXTURES, "self_signed_rsa_cert.pem"),
        os.path.join(FIXTURES, "self_signed_rsa_key.pem"),
        hsts="max-age=31536000; includeSubDomains",
    )
    yield server
    server.stop()

@pytest.fixture
def plain_server():
    server = LocalTlsServer(
        os.path.join(FIXTURES, "self_signed_rsa_cert.pem"),
        os.path.join(FIXTURES, "self_signed_rsa_key.pem"),
    )
    yield server
    server.stop()

@pytest.fixture
def chain_server():
    server = LocalTlsServer(
        os.path.join(FIXTURES, "leaf_chain.pem"),
        os.path.join(FIXTURES, "leaf_key.pem"),
        hsts="max-age=31536000",
    )
    yield server
    server.stop()
