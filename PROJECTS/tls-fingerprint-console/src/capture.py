"""Live capture from a network interface, via Npcap.

Npcap is the packet-capture driver Wireshark installs on Windows. It exposes
the libpcap API, which this module binds directly with ctypes, so the console
gains live capture without taking on a third-party dependency: the only thing
it needs is the driver, and it says so plainly when the driver is absent
instead of failing with an import error somewhere else.

Everything this module returns is a decoded packet dict in exactly the shape
src/pcap.py produces from a capture file, because it calls the same decoder.
The rest of the pipeline therefore cannot tell a live packet from a recorded
one, which is the point.
"""
from __future__ import annotations

import ctypes
import time
from ctypes import POINTER, Structure, byref, c_char, c_char_p, c_int, c_uint, c_void_p

from .pcap import decode_frame

# Where Npcap and the older WinPcap put their library. Npcap on a 64-bit host
# lives under System32\Npcap; the bare System32 path is WinPcap's.
DLL_CANDIDATES = (
    r"C:\Windows\System32\Npcap\wpcap.dll",
    r"C:\Windows\SysWOW64\Npcap\wpcap.dll",
    r"C:\Windows\System32\wpcap.dll",
    r"C:\Windows\SysWOW64\wpcap.dll",
    "wpcap.dll",
)

# Link types this reader decodes, matching src/pcap.py.
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_NULL = 0          # the Npcap loopback adapter reports this
LINKTYPE_LOOP = 108        # OpenBSD loopback

# The ports a TLS handshake normally appears on, used as the default filter so
# the console watches handshakes rather than every packet on the wire.
TLS_PORTS = (443, 8443, 993, 995, 465, 587, 636, 853, 8883, 9443)

# QUIC carries TLS over UDP, so a TCP-only filter silently excludes every
# HTTP/3 handshake -- which is a growing share of real traffic. These are the
# UDP ports QUIC is normally found on.
QUIC_PORTS = (443, 8443, 8883)

DEFAULT_FILTER = (
    "(tcp and (" + " or ".join("port %d" % p for p in TLS_PORTS) + "))"
    " or "
    "(udp and (" + " or ".join("port %d" % p for p in QUIC_PORTS) + "))"
)


class CaptureUnavailable(RuntimeError):
    """Raised when no capture driver is present, or it refuses to open."""


class _timeval(Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _pcap_pkthdr(Structure):
    _fields_ = [("ts", _timeval), ("caplen", c_uint), ("len", c_uint)]


class _pcap_if(Structure):
    pass


_pcap_if._fields_ = [
    ("next", POINTER(_pcap_if)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", c_void_p),
    ("flags", c_uint),
]


def _load():
    last = None
    for path in DLL_CANDIDATES:
        try:
            # WinDLL only exists on Windows. On any other platform the attribute
            # itself is missing, which is an AttributeError rather than an
            # OSError, so catching only OSError let the error escape _load and
            # made available() raise instead of returning False -- which is
            # exactly what CI, running on Linux, would have hit.
            lib = ctypes.WinDLL(path)
        except (OSError, AttributeError) as exc:
            last = exc
            continue
        lib.pcap_findalldevs.argtypes = [POINTER(POINTER(_pcap_if)), c_char_p]
        lib.pcap_findalldevs.restype = c_int
        lib.pcap_freealldevs.argtypes = [POINTER(_pcap_if)]
        lib.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
        lib.pcap_open_live.restype = c_void_p
        lib.pcap_datalink.argtypes = [c_void_p]
        lib.pcap_datalink.restype = c_int
        lib.pcap_compile.argtypes = [c_void_p, c_void_p, c_char_p, c_int, c_uint]
        lib.pcap_compile.restype = c_int
        lib.pcap_setfilter.argtypes = [c_void_p, c_void_p]
        lib.pcap_setfilter.restype = c_int
        lib.pcap_next_ex.argtypes = [c_void_p, POINTER(POINTER(_pcap_pkthdr)),
                                     POINTER(POINTER(c_char))]
        lib.pcap_next_ex.restype = c_int
        lib.pcap_close.argtypes = [c_void_p]
        lib.pcap_geterr.argtypes = [c_void_p]
        lib.pcap_geterr.restype = c_char_p
        return lib
    # `last` holds why the driver would not load, and it used to be thrown away: a
    # machine with Npcap installed but unloadable got the same message as a machine
    # with no Npcap at all, which sends the reader to install what they already have.
    raise CaptureUnavailable(
        "no capture driver could be loaded (looked for wpcap.dll in %s)%s; live capture "
        "needs Npcap present on the machine."
        % (", ".join(DLL_CANDIDATES),
           "; the last attempt failed with %s: %s" % (type(last).__name__, last)
           if last else "")
    )


def available():
    """True when a capture driver can be loaded."""
    try:
        _load()
        return True
    except CaptureUnavailable:
        return False


def list_interfaces():
    """Every capturable interface, as dicts.

    The device name is the handle you pass back in; the description is what a
    person recognises.
    """
    lib = _load()
    errbuf = ctypes.create_string_buffer(256)
    alldevs = POINTER(_pcap_if)()
    if lib.pcap_findalldevs(byref(alldevs), errbuf) != 0:
        raise CaptureUnavailable("could not list interfaces: %s" % errbuf.value.decode("utf-8", "replace"))
    out = []
    node = alldevs
    try:
        index = 0
        while node:
            entry = node.contents
            name = entry.name.decode("utf-8", "replace") if entry.name else ""
            desc = entry.description.decode("utf-8", "replace") if entry.description else ""
            if name:
                out.append({"index": index, "name": name, "description": desc or name})
                index += 1
            node = entry.next
    finally:
        try:
            lib.pcap_freealldevs(alldevs)
        except Exception:
            pass
    return out


def pick_interface(hint=None, interfaces=None):
    """Choose an interface by index, by substring of the description, or by default.

    With no hint this skips the WAN Miniport and Wi-Fi Direct pseudo-adapters,
    which are listed by Npcap but carry no traffic, and prefers a real adapter.
    """
    ifaces = interfaces if interfaces is not None else list_interfaces()
    if not ifaces:
        raise CaptureUnavailable("no interfaces to capture from")
    if hint is None or hint == "":
        skip = ("wan miniport", "wi-fi direct", "virtual", "bluetooth", "teredo")
        real = [i for i in ifaces if not any(s in i["description"].lower() for s in skip)]
        return (real or ifaces)[0]
    text = str(hint).strip()
    if text.isdigit():
        idx = int(text)
        for i in ifaces:
            if i["index"] == idx:
                return i
        raise CaptureUnavailable("no interface with index %d; %d interfaces are available" % (idx, len(ifaces)))
    low = text.lower()
    for i in ifaces:
        if low in i["description"].lower() or low in i["name"].lower():
            return i
    raise CaptureUnavailable("no interface matching %r; %d interfaces are available" % (hint, len(ifaces)))


class LiveCapture:
    """A live capture handle.

    Use as a context manager. ``packets()`` yields decoded packet dicts and
    blocks until the next one arrives or the read times out, so a caller can
    check a stop flag between yields.
    """

    def __init__(self, device, snaplen=65535, promiscuous=True, timeout_ms=250, bpf=None):
        self.device = device
        self.snaplen = snaplen
        self.promiscuous = promiscuous
        self.timeout_ms = timeout_ms
        self.bpf = DEFAULT_FILTER if bpf is None else bpf
        self._lib = None
        self._handle = None
        self.linktype = None
        self.filter_applied = None
        self.stats = {"packets": 0, "bytes": 0, "started": None, "errors": 0}

    def open(self):
        lib = _load()
        errbuf = ctypes.create_string_buffer(256)
        handle = lib.pcap_open_live(
            self.device.encode("utf-8"), self.snaplen,
            1 if self.promiscuous else 0, self.timeout_ms, errbuf,
        )
        if not handle:
            raise CaptureUnavailable(
                "could not open %s: %s (live capture normally needs an elevated shell)"
                % (self.device, errbuf.value.decode("utf-8", "replace"))
            )
        self._lib, self._handle = lib, handle
        self.linktype = lib.pcap_datalink(handle)
        self.stats["started"] = time.time()
        if self.bpf:
            self._apply_filter(self.bpf)
        return self

    def _apply_filter(self, expression):
        """Install a BPF filter. A filter that will not compile is reported, not ignored."""
        lib, handle = self._lib, self._handle
        program = ctypes.create_string_buffer(4096)  # struct bpf_program is small; over-allocate
        if lib.pcap_compile(handle, program, expression.encode("utf-8"), 1, 0) != 0:
            self.filter_applied = None
            raise CaptureUnavailable(
                "the filter %r did not compile: %s"
                % (expression, (lib.pcap_geterr(handle) or b"").decode("utf-8", "replace"))
            )
        if lib.pcap_setfilter(handle, program) != 0:
            self.filter_applied = None
            raise CaptureUnavailable(
                "the filter %r was refused: %s"
                % (expression, (lib.pcap_geterr(handle) or b"").decode("utf-8", "replace"))
            )
        self.filter_applied = expression

    def packets(self):
        """Yield decoded packet dicts until the caller stops iterating or close() is called."""
        if self._handle is None:
            raise CaptureUnavailable("capture is not open")
        lib, handle = self._lib, self._handle
        header = POINTER(_pcap_pkthdr)()
        data = POINTER(c_char)()
        while self._handle is not None:
            rc = lib.pcap_next_ex(handle, byref(header), byref(data))
            if rc == 0:
                continue                      # read timeout, no packet this round
            if rc == -2:
                return                        # capture closed underneath us
            if rc != 1:
                self.stats["errors"] += 1
                return
            caplen = header.contents.caplen
            raw = ctypes.string_at(data, caplen)
            self.stats["packets"] += 1
            self.stats["bytes"] += caplen
            ts = header.contents.ts.tv_sec + header.contents.ts.tv_usec / 1_000_000.0
            packet = self._decode(raw, ts)
            if packet is not None:
                yield packet

    def _decode(self, raw, ts):
        """Decode a frame, tolerating the link types Npcap actually reports."""
        if self.linktype == LINKTYPE_NULL or self.linktype == LINKTYPE_LOOP:
            # The loopback adapter prefixes a 4-byte address family; the rest is
            # an IP packet, which the raw-IP path already understands.
            return decode_frame(raw[4:], LINKTYPE_RAW, ts)
        return decode_frame(raw, self.linktype, ts)

    def close(self):
        if self._handle is not None and self._lib is not None:
            try:
                self._lib.pcap_close(self._handle)
            except Exception:
                pass
        self._handle = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *exc):
        self.close()
        return False
