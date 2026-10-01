# Architecture

1. The command line accepts a host, port, and timeout.
2. A TCP socket connects to the target.
3. Python's default SSL context wraps the socket and validates the peer.
4. The scanner reads the negotiated session and certificate fields.
5. The command line prints the collected values.

## Follow one run

`socket.create_connection()` opens TCP. A default SSL context wraps the connection with the requested server name, preserving SNI and certificate verification. The scanner reads the negotiated session and formats the nested certificate fields into readable text. Certificate times use the SSL parser so the result does not depend on the operating-system language.

Provide a hostname, not a full URL. The default port is 443 and the default timeout is five seconds. This command makes a real network connection, so its output depends on the endpoint and your network. The implementation uses the Python standard library and needs no project-specific package installation.

[Back to the project guide](../README.md)
