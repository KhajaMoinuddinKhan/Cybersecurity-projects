"""Inspect a TLS connection and certificate."""
from __future__ import annotations

import argparse
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

def parse_certificate_time(value: str | None) -> str | None:
    """Convert certificate time text to ISO format."""

    if not value:
        return None
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), timezone.utc).isoformat()

def certificate_subject(cert: dict[str, Any]) -> str:
    """Format the certificate subject."""

    parts = [
        f"{key}={value}"
        for group in cert.get("subject", ())
        for key, value in group
    ]
    return ", ".join(parts) or "Unavailable"

def certificate_issuer(cert: dict[str, Any]) -> str:
    """Format the certificate issuer."""

    parts = [
        f"{key}={value}"
        for group in cert.get("issuer", ())
        for key, value in group
    ]
    return ", ".join(parts) or "Unavailable"

def scan(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """Connect with TLS verification and collect session details."""

    # The default context checks the certificate and hostname.
    context = ssl.create_default_context()

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

def main() -> None:
    """Inspect a TLS endpoint and print the result."""

    parser = argparse.ArgumentParser(description="Inspect a TLS connection safely.")
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    try:
        result = scan(args.host, args.port, args.timeout)
    except (OSError, ssl.SSLError, ValueError, OverflowError) as exc:
        raise SystemExit(f"TLS inspection failed: {exc}") from exc

    for key, value in result.items():
        print(f"{key}: {value}")

if __name__ == "__main__":
    main()
