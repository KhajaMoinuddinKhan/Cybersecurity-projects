# Implementation

- `ssl.create_default_context()` supplies certificate and hostname checks.
- `socket.create_connection()` handles the TCP connection and timeout.
- `wrap_socket()` starts TLS with the requested server name.
- Helper functions flatten nested certificate subject and issuer data.
- Certificate expiry text is converted to an ISO 8601 UTC timestamp.

## Inputs and failure handling

Provide a hostname, not a full URL. The default port is 443 and the default timeout is five seconds. This command makes a real network connection, so its output depends on the endpoint and your network. The implementation uses the Python standard library and needs no project-specific package installation.

For timeouts, check the hostname, port, connectivity, and firewall before increasing `--timeout`. If a private lab uses its own certificate authority, configure the appropriate trusted CA in your environment. Do not treat a verification failure as a reason to remove validation from the code.

[Back to the project guide](../README.md)
