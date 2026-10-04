"""Pure-Python pcap / pcapng reader and TCP stream reassembly.

Standard library only (``struct`` + ``socket``); no scapy, no dpkt.

Supported:

* classic pcap (both endiannesses, microsecond and nanosecond magic) with link
  types EN10MB (1) and RAW (101)
* pcapng with Interface Description Blocks (incl. ``if_tsresol``) and Enhanced
  Packet Blocks
* Ethernet II (IPv4 / IPv6 / 802.1Q VLAN tags, including stacked tags)
* IPv4 (IHL/options) and IPv6 (40-byte header plus common extension headers)
* TCP (full option decoding: MSS, window scale, ...) and UDP

Every low-level ``struct`` access is bounds-checked: malformed or truncated
input raises :class:`ValueError` with a readable message rather than a raw
``struct.error``.
"""

import socket
import struct

_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000000),
    b"\xa1\xb2\xc3\xd4": (">", 1000000),
    b"\x4d\x3c\xb2\xa1": ("<", 1000000000),
    b"\xa1\xb2\x3c\x4d": (">", 1000000000),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)

IPPROTO_TCP = 6
IPPROTO_UDP = 17

_FLAG_NAMES = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)


def read_pcap(path):
    """Read a pcap or pcapng file and return a list of packet dicts."""
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 4:
        raise ValueError("file too short to be a pcap/pcapng capture")
    magic = data[:4]
    if magic == _PCAPNG_MAGIC:
        return _read_pcapng(data)
    if magic in _PCAP_MAGIC:
        return _read_classic(data, magic)
    raise ValueError("unrecognized capture magic: %r" % (magic,))


def reassemble_streams(packets):
    """Group TCP payloads by direction (src_ip, src_port -> dst_ip, dst_port).

    Packets are ordered by sequence number and pure ACKs (empty payload) are
    dropped.
    """
    groups = {}
    order = []
    for pkt in packets:
        if pkt.get("protocol") != "tcp":
            continue
        payload = pkt.get("payload") or b""
        if not payload:
            continue
        key = (pkt["src_ip"], pkt["src_port"], pkt["dst_ip"], pkt["dst_port"])
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(pkt)
    streams = []
    for key in order:
        members = sorted(groups[key], key=lambda p: p["seq"])
        streams.append({
            "src_ip": key[0],
            "src_port": key[1],
            "dst_ip": key[2],
            "dst_port": key[3],
            "payload": b"".join(m["payload"] for m in members),
        })
    return streams


# ---------------------------------------------------------------------------
# classic pcap
# ---------------------------------------------------------------------------

def _read_classic(data, magic):
    endian, div = _PCAP_MAGIC[magic]
    if len(data) < 24:
        raise ValueError("truncated pcap global header")
    _vmaj, _vmin, _tz, _sf, _snap, network = struct.unpack_from(
        endian + "HHiIII", data, 4)
    packets = []
    off = 24
    n = len(data)
    while off < n:
        if off + 16 > n:
            raise ValueError("truncated pcap packet header")
        ts_sec, ts_frac, incl, _orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        if incl > n - off:
            raise ValueError("truncated pcap packet data")
        raw = data[off:off + incl]
        off += incl
        ts = ts_sec + ts_frac / div
        pkt = _decode_link(raw, network, ts)
        if pkt is not None:
            packets.append(pkt)
    return packets


# ---------------------------------------------------------------------------
# pcapng
# ---------------------------------------------------------------------------

def _read_pcapng(data):
    n = len(data)
    if n < 12:
        raise ValueError("truncated pcapng section header")
    bom = data[8:12]
    if bom == struct.pack("<I", 0x1A2B3C4D):
        endian = "<"
    elif bom == struct.pack(">I", 0x1A2B3C4D):
        endian = ">"
    else:
        raise ValueError("bad pcapng byte-order magic")
    packets = []
    interfaces = []
    off = 0
    while off < n:
        if off + 8 > n:
            raise ValueError("truncated pcapng block header")
        btype = struct.unpack_from(endian + "I", data, off)[0]
        blen = struct.unpack_from(endian + "I", data, off + 4)[0]
        if blen < 12 or off + blen > n:
            raise ValueError("invalid pcapng block length")
        body = data[off + 8:off + blen - 4]
        if btype == 0x0A0D0D0A:
            interfaces = []
            if len(body) >= 4:
                if body[0:4] == struct.pack("<I", 0x1A2B3C4D):
                    endian = "<"
                elif body[0:4] == struct.pack(">I", 0x1A2B3C4D):
                    endian = ">"
        elif btype == 1:  # Interface Description Block
            if len(body) < 8:
                raise ValueError("truncated pcapng interface block")
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            div = _idb_tsresol(body, endian, 1000000.0)
            interfaces.append({"linktype": linktype, "div": div})
        elif btype == 6:  # Enhanced Packet Block
            if len(body) < 20:
                raise ValueError("truncated pcapng enhanced packet block")
            iface_id = struct.unpack_from(endian + "I", body, 0)[0]
            ts_high = struct.unpack_from(endian + "I", body, 4)[0]
            ts_low = struct.unpack_from(endian + "I", body, 8)[0]
            caplen = struct.unpack_from(endian + "I", body, 12)[0]
            pkt = body[20:20 + caplen]
            if iface_id < len(interfaces):
                linktype = interfaces[iface_id]["linktype"]
                div = interfaces[iface_id]["div"]
            else:
                linktype, div = LINKTYPE_ETHERNET, 1000000.0
            ts = ((ts_high << 32) | ts_low) / div
            decoded = _decode_link(pkt, linktype, ts)
            if decoded is not None:
                packets.append(decoded)
        elif btype == 3:  # Simple Packet Block
            if interfaces and len(body) >= 4:
                orig_len = struct.unpack_from(endian + "I", body, 0)[0]
                pkt = body[4:4 + orig_len]
                decoded = _decode_link(pkt, interfaces[0]["linktype"], 0.0)
                if decoded is not None:
                    packets.append(decoded)
        off += blen
    return packets


def _idb_tsresol(body, endian, default):
    off = 8
    n = len(body)
    while off + 4 <= n:
        code = struct.unpack_from(endian + "H", body, off)[0]
        olen = struct.unpack_from(endian + "H", body, off + 2)[0]
        val = body[off + 4:off + 4 + olen]
        if code == 0:
            break
        if code == 9 and val:
            v = val[0]
            if v & 0x80:
                return float(2 ** (v & 0x7F))
            return float(10 ** v)
        off += 4 + ((olen + 3) // 4) * 4
    return default


# ---------------------------------------------------------------------------
# link / network / transport decoding
# ---------------------------------------------------------------------------

def decode_frame(raw, linktype, ts):
    """Decode one link-layer frame into a packet dict.

    Public wrapper over the same path the file reader uses, so a frame captured
    live and a frame read from a capture file are decoded by identical code.
    Returns None for a frame that carries no IPv4/IPv6 packet.
    """
    return _decode_link(raw, linktype, ts)


def _decode_link(raw, linktype, ts):
    if linktype == LINKTYPE_ETHERNET:
        return _parse_ethernet(raw, ts)
    if linktype == LINKTYPE_RAW:
        return _parse_raw_ip(raw, ts)
    # Returning None here silently dropped every packet in the file and made an
    # unreadable capture look like an empty one.  Naming the link type is the
    # difference between "nothing happened" and "this file is in a format I do
    # not decode".
    raise ValueError(
        "unsupported link type %d: this reader decodes Ethernet (%d) and raw IP (%d); "
        "re-export the capture in one of those formats"
        % (linktype, LINKTYPE_ETHERNET, LINKTYPE_RAW)
    )


def _parse_raw_ip(raw, ts):
    if not raw:
        return None
    version = raw[0] >> 4
    if version == 4:
        return _finish_ipv4(raw, 0, ts)
    if version == 6:
        return _finish_ipv6(raw, 0, ts)
    return None


def _parse_ethernet(raw, ts):
    if len(raw) < 14:
        return None
    ethertype = struct.unpack_from(">H", raw, 12)[0]
    off = 14
    while ethertype in VLAN_TPIDS:
        if len(raw) < off + 4:
            return None
        ethertype = struct.unpack_from(">H", raw, off + 2)[0]
        off += 4
    if ethertype == ETHERTYPE_IPV4:
        return _finish_ipv4(raw, off, ts)
    if ethertype == ETHERTYPE_IPV6:
        return _finish_ipv6(raw, off, ts)
    return None


def _finish_ipv4(data, off, ts):
    header = _ipv4_header(data, off)
    if header is None:
        return None
    proto, src, dst, t_off, iplen = header
    return _parse_transport(proto, src, dst, data, t_off, iplen, ts)


def _finish_ipv6(data, off, ts):
    header = _ipv6_header(data, off)
    if header is None:
        return None
    proto, src, dst, t_off, iplen = header
    return _parse_transport(proto, src, dst, data, t_off, iplen, ts)


def _ipv4_header(data, off):
    if len(data) < off + 20:
        return None
    ver_ihl = data[off]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < off + ihl:
        return None
    total_len = struct.unpack_from(">H", data, off + 2)[0]
    proto = data[off + 9]
    src = _ip4_str(data[off + 12:off + 16])
    dst = _ip4_str(data[off + 16:off + 20])
    ip_payload_len = total_len - ihl
    if ip_payload_len < 0:
        ip_payload_len = None
    return proto, src, dst, off + ihl, ip_payload_len


def _ipv6_header(data, off):
    if len(data) < off + 40:
        return None
    if data[off] >> 4 != 6:
        return None
    payload_len = struct.unpack_from(">H", data, off + 4)[0]
    next_header = data[off + 6]
    src = _ip6_str(data[off + 8:off + 24])
    dst = _ip6_str(data[off + 24:off + 40])
    p = off + 40
    consumed = 0
    while next_header in (0, 43, 44, 51, 60):
        if len(data) < p + 2:
            return None
        if next_header == 44:
            hlen = 8
        elif next_header == 51:
            hlen = (data[p + 1] + 2) * 4
        else:
            hlen = (data[p + 1] + 1) * 8
        next_header = data[p]
        p += hlen
        consumed += hlen
        if len(data) < p:
            return None
    ip_payload_len = payload_len - consumed
    if payload_len == 0:
        ip_payload_len = None
    if ip_payload_len is not None and ip_payload_len < 0:
        ip_payload_len = None
    return next_header, src, dst, p, ip_payload_len


def _parse_transport(proto, src, dst, data, off, ip_payload_len, ts):
    if proto == IPPROTO_TCP:
        if len(data) < off + 20:
            return None
        sport, dport, seq, ack = struct.unpack_from(">HHII", data, off)
        data_off = (data[off + 12] >> 4) * 4
        if data_off < 20 or len(data) < off + data_off:
            return None
        flags = _tcp_flags(data[off + 13])
        window = struct.unpack_from(">H", data, off + 14)[0]
        kinds, mss, wscale = _parse_tcp_options(data[off + 20:off + data_off])
        avail = len(data) - off - data_off
        if ip_payload_len is None:
            plen = avail
        else:
            plen = ip_payload_len - data_off
        if plen < 0:
            plen = 0
        if plen > avail:
            plen = avail
        payload = bytes(data[off + data_off:off + data_off + plen])
        return _make_packet(ts, src, dst, sport, dport, "tcp", flags, seq, ack,
                            window, kinds, mss, wscale, payload)
    if proto == IPPROTO_UDP:
        if len(data) < off + 8:
            return None
        sport, dport, ulen = struct.unpack_from(">HHH", data, off)
        avail = len(data) - off - 8
        plen = ulen - 8
        if plen < 0 or plen > avail:
            plen = max(0, avail)
        payload = bytes(data[off + 8:off + 8 + plen])
        return _make_packet(ts, src, dst, sport, dport, "udp", "", 0, 0, 0,
                            [], None, None, payload)
    return None


def _make_packet(ts, src, dst, sport, dport, proto, flags, seq, ack, window,
                 options, mss, wscale, payload):
    return {
        "ts": ts,
        "src_ip": src,
        "dst_ip": dst,
        "src_port": sport,
        "dst_port": dport,
        "protocol": proto,
        "flags": flags,
        "seq": seq,
        "ack": ack,
        "window": window,
        "tcp_options": list(options),
        "mss": mss,
        "window_scale": wscale,
        "payload": payload,
    }


def _parse_tcp_options(opts):
    kinds = []
    mss = None
    wscale = None
    i = 0
    n = len(opts)
    while i < n:
        kind = opts[i]
        if kind == 0:  # End of option list: terminate, do not record padding
            break
        if kind == 1:  # No-op: significant for fingerprints, record it
            kinds.append(1)
            i += 1
            continue
        if i + 1 >= n:
            kinds.append(kind)
            break
        length = opts[i + 1]
        if length < 2 or i + length > n:
            kinds.append(kind)
            break
        value = opts[i + 2:i + length]
        kinds.append(kind)
        if kind == 2 and len(value) >= 2:
            mss = struct.unpack_from(">H", value, 0)[0]
        elif kind == 3 and len(value) >= 1:
            wscale = value[0]
        i += length
    return kinds, mss, wscale


def _tcp_flags(byte):
    return ",".join(name for bit, name in _FLAG_NAMES if byte & bit)


def _ip4_str(raw):
    return ".".join(str(b) for b in raw)


def _ip6_str(raw):
    groups = [(raw[i] << 8) | raw[i + 1] for i in range(0, 16, 2)]
    best_start = -1
    best_len = 0
    cur_start = -1
    cur_len = 0
    for idx, grp in enumerate(groups):
        if grp == 0:
            if cur_start == -1:
                cur_start = idx
                cur_len = 1
            else:
                cur_len += 1
            if cur_len > best_len:
                best_len = cur_len
                best_start = cur_start
        else:
            cur_start = -1
            cur_len = 0
    if best_len < 2:
        return ":".join("%x" % g for g in groups)
    head = ":".join("%x" % g for g in groups[:best_start])
    tail = ":".join("%x" % g for g in groups[best_start + best_len:])
    return head + "::" + tail
