# Architecture

1. The command line accepts a host, port, and timeout.
2. A TCP socket connects to the target.
3. Python's default SSL context wraps the socket and validates the peer.
4. The scanner reads the negotiated session and certificate fields.
5. The command line prints the collected values.
