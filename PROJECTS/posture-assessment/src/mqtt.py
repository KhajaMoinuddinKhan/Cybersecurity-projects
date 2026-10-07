"""Just enough MQTT to ask a broker whether it will talk to anybody.

MQTT is the protocol the IoT arm exists for: it is what small devices speak, and its
most common deployment mistake is a broker that accepts a connection from anyone.
That question -- "will you talk to me without a credential?" -- needs exactly one
packet exchange, and implementing it here rather than importing a client means the
assessment needs no third-party package and the tool can explain what it sent.

MQTT 3.1.1, sections 3.1 (CONNECT) and 3.2 (CONNACK). The return codes in CONNACK
are the answer: 0 is accepted, 4 is a bad username or password, and 5 is not
authorized. The difference between 4 and 5 matters -- one says the broker checked and
refused, the other says it does not trust the client at all -- and both mean the
credential was not accepted, which is the only thing the assessment needs.
"""

from __future__ import annotations

import socket
import struct

__all__ = ["MqttError", "connect_result", "RETURN_CODES", "encode_string",
           "encode_remaining_length", "build_connect"]

RETURN_CODES = {
    0: "accepted",
    1: "refused: unacceptable protocol version",
    2: "refused: identifier rejected",
    3: "refused: server unavailable",
    4: "refused: bad username or password",
    5: "refused: not authorized",
}

PROTOCOL_LEVEL = 4          # 3.1.1; 3 is 3.1, which predates the username field
DEFAULT_TIMEOUT = 4.0


class MqttError(OSError):
    """The broker did not answer in a way MQTT describes."""


def encode_remaining_length(length: int) -> bytes:
    """MQTT's variable-length integer: seven bits per byte, high bit means more."""
    if length < 0:
        raise ValueError("a remaining length cannot be negative")
    encoded = bytearray()
    while True:
        digit = length % 128
        length //= 128
        if length:
            digit |= 0x80
        encoded.append(digit)
        if not length:
            return bytes(encoded)


def encode_string(value: str) -> bytes:
    payload = value.encode("utf-8")
    if len(payload) > 65535:
        raise ValueError("an MQTT string cannot exceed 65535 bytes")
    return struct.pack("!H", len(payload)) + payload


def build_connect(client_id: str, username: str | None = None,
                  password: str | None = None, clean_session: bool = True) -> bytes:
    """A CONNECT packet. Omitting both credentials is the anonymous case."""
    flags = 0
    if clean_session:
        flags |= 0x02
    payload = encode_string(client_id)
    if username is not None:
        flags |= 0x80
        payload += encode_string(username)
    if password is not None:
        flags |= 0x40
        payload += encode_string(password)

    variable = (encode_string("MQTT") + bytes([PROTOCOL_LEVEL, flags])
                + struct.pack("!H", 60))
    body = variable + payload
    return bytes([0x10]) + encode_remaining_length(len(body)) + body


def _read_remaining_length(sock) -> int:
    multiplier = 1
    value = 0
    for _ in range(4):
        chunk = sock.recv(1)
        if not chunk:
            raise MqttError("the connection closed before the broker answered")
        digit = chunk[0]
        value += (digit & 127) * multiplier
        if not digit & 0x80:
            return value
        multiplier *= 128
    raise MqttError("the remaining length is malformed")


def connect_result(host: str, port: int, username: str | None = None,
                   password: str | None = None, timeout: float = DEFAULT_TIMEOUT,
                   client_id: str = "posture-assessment") -> dict:
    """Send one CONNECT and return what the broker said.

    Returns a dict rather than raising for a refusal, because a refusal is the
    answer being sought. An unreachable broker is an error, and is reported as one --
    "no answer" and "it let me in" are opposite conclusions and must not be confused.
    """
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(build_connect(client_id, username, password))
        header = sock.recv(1)
        if not header:
            raise MqttError("the broker closed the connection without answering")
        if header[0] != 0x20:
            raise MqttError("expected a CONNACK (0x20), got 0x%02x" % header[0])
        length = _read_remaining_length(sock)
        body = b""
        while len(body) < length:
            chunk = sock.recv(length - len(body))
            if not chunk:
                break
            body += chunk
        if len(body) < 2:
            raise MqttError("the CONNACK was too short to carry a return code")
        code = body[1]
        return {"ok": True, "connected": code == 0, "code": code,
                "meaning": RETURN_CODES.get(code, "unknown return code %d" % code),
                "session_present": bool(body[0] & 1)}
    except MqttError as exc:
        return {"ok": False, "connected": False, "error": "protocol",
                "detail": str(exc)}
    except (socket.timeout, OSError) as exc:
        return {"ok": False, "connected": False, "error": type(exc).__name__,
                "detail": str(exc)[:200]}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
