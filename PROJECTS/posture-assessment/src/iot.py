"""The IoT assessor: a real broker, asked real questions.

The other three assessors read artifacts. This one talks to a service, because the
questions that matter about a small device are not answerable from a configuration
file: whether the broker accepts a connection from anybody, and whether it accepts
the credential printed in its own manual, are properties of the running thing.

The default-credential list is the published one. These pairs are in device manuals,
in firmware images and in every list of them -- which is exactly what makes them
worth trying and exactly why a device that accepts one is compromised already. The
list is deliberately short: it is the set that is actually widespread, not every
pair anybody has ever shipped, because a longer list would be a slower way of asking
the same question.

Nothing here changes anything on the device. Every check is a connection attempt and
a disconnection, and the audit is a read of the answer.
"""

from __future__ import annotations

from pathlib import Path

from .findings import Evidence, make
from .mqtt import connect_result

__all__ = ["assess_broker", "assess_device", "DEFAULT_CREDENTIALS", "MQTT_PORT"]

ENVIRONMENT = "iot"

MQTT_PORT = 1883
MQTT_TLS_PORT = 8883

# Published default credentials. Documented in vendor manuals and collected in the
# malware that made them famous; a device that accepts one of these has no
# authentication in any meaningful sense.
DEFAULT_CREDENTIALS = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "public"),
    ("admin", "1234"),
    ("admin", ""),
    ("root", "root"),
    ("root", "admin"),
    ("root", ""),
    ("user", "user"),
    ("guest", "guest"),
    ("support", "support"),
    ("service", "service"),
    ("pi", "raspberry"),
)

# Interfaces that are not reachable from a network. A broker bound to one of these is
# not exposed; one bound to anything else is.
LOOPBACK = ("127.", "::1", "localhost")


def _is_loopback(host: str) -> bool:
    return host.startswith(LOOPBACK)


def assess_broker(policy, host: str, port: int = MQTT_PORT, timeout: float = 4.0,
                  try_defaults: bool = True) -> list:
    """Ask a live MQTT broker whether it will talk to anybody, and to whom."""
    findings = []

    # Exposure is a property of the address the broker is on, not of whether it
    # answers right now. Checking it after the connection meant an unreachable broker
    # was never reported as exposed, which is the wrong way round: a broker on a
    # public address is exposed whether or not it replies to this tool today.
    if not _is_loopback(host):
        evidence = Evidence()
        evidence.add("binding", "the broker is addressed as %s" % host,
                     "a management interface on a network rather than on the device")
        findings.append(make(
            policy.by_id("no-exposed-management-port"), ENVIRONMENT,
            "%s:%d" % (host, port),
            "The broker is addressed somewhere other than loopback, so its management "
            "interface is on the network rather than confined to the device.", evidence,
            location="%s:%d" % (host, port)))

    anonymous = connect_result(host, port, timeout=timeout,
                               client_id="posture-assessment-anon")
    if not anonymous.get("ok"):
        # No answer is not the same as a refusal, and reporting it as one would turn
        # an unreachable broker into a clean bill of health.
        evidence = Evidence()
        evidence.add("connection", "%s:%d" % (host, port),
                     "%s: %s" % (anonymous.get("error"), anonymous.get("detail", "")))
        findings.append(make(
            policy.by_id("no-anonymous-access"), ENVIRONMENT, "%s:%d" % (host, port),
            "The broker did not answer, so nothing can be concluded about how it "
            "authenticates. This is reported as unknown rather than as clear, because "
            "an unreachable service and a secure one look identical from here.",
            evidence, location="%s:%d" % (host, port)))
        return findings

    if anonymous.get("connected"):
        evidence = Evidence()
        evidence.add("connect", "CONNECT with no username and no password",
                     "CONNACK code 0: %s" % anonymous["meaning"])
        evidence.add("observation",
                     "the broker accepted a client that presented no credential at all", "")
        findings.append(make(
            policy.by_id("no-anonymous-access"), ENVIRONMENT, "%s:%d" % (host, port),
            "The broker accepts connections from anyone who can reach the port. There "
            "is no credential to guess because none is required, which means every "
            "device that can reach it can read and publish on every topic it allows.",
            evidence, location="%s:%d" % (host, port)))

    if try_defaults:
        for username, password in DEFAULT_CREDENTIALS:
            result = connect_result(host, port, username, password, timeout=timeout,
                                    client_id="posture-assessment-defaults")
            if result.get("connected"):
                evidence = Evidence()
                evidence.add("connect",
                             "CONNECT with username=%r" % username,
                             "CONNACK code 0: %s" % result["meaning"])
                evidence.add("observation",
                             "the credential was accepted by the running broker", "")
                findings.append(make(
                    policy.by_id("no-default-credentials"), ENVIRONMENT,
                    "%s:%d" % (host, port),
                    "The broker accepted a published default credential. It is not a "
                    "weak credential, it is a known one: it is in the manual, in the "
                    "firmware image and in every list of them. The check does not "
                    "record which one succeeded beyond the account name, because the "
                    "finding is that the account exists, not the password.",
                    evidence, location="%s:%d" % (host, port)))
                break

    return findings


def assess_device(policy, device: dict, target: str = "") -> list:
    """Check a device's declared configuration.

    The inventory is the organisation's own record of what it has, which is the only
    place a firmware support window can come from -- a device does not announce it
    over the network, and pretending to discover it would be inventing an answer.
    """
    findings = []
    name = device.get("name") or target or "device"
    where = "device: %s" % name

    update = device.get("firmware_update") or {}
    if not isinstance(update, dict) or not update.get("url"):
        evidence = Evidence()
        evidence.add("inventory", where, "no firmware_update url is recorded")
        findings.append(make(
            policy.by_id("firmware-update-path"), ENVIRONMENT, name,
            "The inventory records no firmware update source for this device, so there "
            "is no path by which a vulnerability in it can be fixed.", evidence,
            location=where))
    else:
        url = str(update["url"])
        signed = bool(update.get("signature_verified"))
        encrypted = url.lower().startswith("https://")
        if not (signed and encrypted):
            evidence = Evidence()
            evidence.add("inventory", where, "firmware_update.url = %s" % url)
            evidence.add("observation",
                         "signature_verified is %s and the transport is %s"
                         % (update.get("signature_verified"), "TLS" if encrypted else "plaintext"),
                         "")
            findings.append(make(
                policy.by_id("firmware-update-path"), ENVIRONMENT, name,
                "The device has an update path, and it does not both use an encrypted "
                "transport and verify a signature on the image. An update a device "
                "accepts without checking is a way to install whatever somebody else "
                "sends.", evidence, location=where))

    for key in ("password", "secret", "token", "api_key", "private_key"):
        value = device.get(key)
        if value and str(value).strip() and not str(value).startswith(("${", "vault:")):
            evidence = Evidence()
            evidence.add("inventory", "%s %s" % (where, key), "a literal value")
            findings.append(make(
                policy.by_id("no-secrets-in-configuration"), ENVIRONMENT, name,
                "A credential is written into the device inventory. The inventory is a "
                "file, and a file has copies.", evidence, location=where))
            break
    return findings


def load_inventory(path: str | Path) -> list:
    """Read a device inventory: a JSON list, or an object with a `devices` key."""
    import json
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError("no such inventory: %s" % path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("devices") or []
    if not isinstance(data, list):
        raise ValueError("an inventory should be a list of devices")
    return [d for d in data if isinstance(d, dict)]
