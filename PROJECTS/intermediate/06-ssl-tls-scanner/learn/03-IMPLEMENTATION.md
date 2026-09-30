# Implementation

- `ssl.create_default_context()` supplies certificate and hostname checks.
- `socket.create_connection()` handles the TCP connection and timeout.
- `wrap_socket()` starts TLS with the requested server name.
- Helper functions flatten nested certificate subject and issuer data.
- Certificate expiry text is converted to an ISO 8601 UTC timestamp.
