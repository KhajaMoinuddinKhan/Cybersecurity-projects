"""Inspect a TLS session and peer certificate."""
from __future__ import annotations

import argparse
import socket
import ssl
from datetime import datetime, timezone
from typing import Any


# [SECTION] Certificate formatting helpers
def parse_certificate_time(value: str | None) -> str | None:
    """Convert OpenSSL-style certificate time text into an ISO-8601 timestamp."""

    if not value:
        return None
    parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    return parsed.replace(tzinfo=timezone.utc).isoformat()


def certificate_subject(cert: dict[str, Any]) -> str:
    """Flatten the nested certificate subject fields into readable text."""

    parts = [
        f"{key}={value}"
        for group in cert.get("subject", ())
        for key, value in group
    ]
    return ", ".join(parts) or "Unavailable"


def certificate_issuer(cert: dict[str, Any]) -> str:
    """Flatten the nested certificate issuer fields into readable text."""

    parts = [
        f"{key}={value}"
        for group in cert.get("issuer", ())
        for key, value in group
    ]
    return ", ".join(parts) or "Unavailable"


# [SECTION] TLS connection inspection
def scan(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """Connect with certificate verification enabled and collect TLS metadata."""

    # The default SSL context validates the certificate chain and hostname.
    context = ssl.create_default_context()

    # First open a TCP connection, then wrap it in a verified TLS session.
    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            cert = tls_socket.getpeercert()
            cipher = tls_socket.cipher()

            return {
                "host": host,
                "port": port,
                "tls_version": tls_socket.version(),
                "cipher": cipher[0] if cipher else None,
                "certificate_subject": certificate_subject(cert),
                "certificate_issuer": certificate_issuer(cert),
                "certificate_expires": parse_certificate_time(cert.get("notAfter")),
            }


# [SECTION] Command-line interface
def main() -> None:
    """Inspect a TLS endpoint and print the negotiated security details."""

    parser = argparse.ArgumentParser(description="Inspect a TLS connection safely.")
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    try:
        result = scan(args.host, args.port, args.timeout)
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise SystemExit(f"TLS inspection failed: {exc}") from exc

    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
