"""RFC 9001 Appendix A tests for QUIC Initial parsing and decryption.

Every expected value -- the protected client Initial packet, the derived
secrets, the unprotected header and the recovered ClientHello -- is taken
verbatim from RFC 9001 Appendix A.  Nothing is mocked: the packet is really
decrypted with the real HKDF and AES primitives, and the recovered ClientHello
is really fed to ``src.tls.parse_client_hello`` and ``src.ja4``.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import src.quic as quic  # noqa: E402
from src.ja4 import ja4  # noqa: E402
from src.tls import parse_client_hello  # noqa: E402


def _hex(text):
    return bytes.fromhex("".join(text.split()))


DCID = bytes.fromhex("8394c8f03e515708")

INITIAL_SECRET = "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
CLIENT_INITIAL_SECRET = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
KEY = "1f369613dd76d5467730efcbe3b1a22d"
IV = "fa044b2f42a3fd3b46fb255c"
HP = "9f50449e04a0e810283a1e9933adedd2"

# RFC 9001 A.2: the protected client Initial packet.
PROTECTED = _hex("""
c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934
""")

# RFC 9001 A.3: the unprotected header (packet number 2, pn_length 4).
EXPECTED_HEADER = _hex("c300000001088394c8f03e5157080000449e00000002")

# RFC 9001 A.3: the CRYPTO frame carries this exact ClientHello.
EXPECTED_CLIENT_HELLO = _hex("""
010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff
""")


# ---------------------------------------------------------------------------
# HKDF / Initial secrets
# ---------------------------------------------------------------------------

def test_derive_initial_keys_matches_rfc_vector():
    keys = quic.derive_initial_keys(DCID)
    assert keys["initial_secret"].hex() == INITIAL_SECRET
    assert keys["client_initial_secret"].hex() == CLIENT_INITIAL_SECRET
    assert keys["key"].hex() == KEY
    assert keys["iv"].hex() == IV
    assert keys["hp"].hex() == HP


def test_derive_initial_keys_rejects_unknown_version():
    with pytest.raises(ValueError):
        quic.derive_initial_keys(DCID, version=0x12345678)


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------

def test_parse_packets_protected_initial():
    packets = quic.parse_packets(PROTECTED)
    assert len(packets) == 1
    pkt = packets[0]
    assert pkt["long_header"] is True
    assert pkt["packet_type"] == "initial"
    assert pkt["version"] == quic.QUIC_V1
    assert pkt["dcid"] == DCID
    assert pkt["scid"] == b""
    assert pkt["pn_offset"] == 18
    assert len(pkt["raw"]) == len(PROTECTED)


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------

def test_decrypt_initial_vector():
    keys = quic.derive_initial_keys(DCID)
    pkt = quic.parse_packets(PROTECTED)[0]
    out = quic.decrypt_initial(pkt, keys)
    assert out["packet_number"] == 2
    assert out["header"] == EXPECTED_HEADER
    frames = quic.crypto_frames(out["plaintext"])
    assert frames
    assert frames[0]["offset"] == 0
    assert frames[0]["data"].startswith(b"\x01")


def test_client_hello_from_datagram_equals_vector():
    result = quic.client_hello_from_datagram(PROTECTED)
    assert result is not None
    assert result["version"] == quic.QUIC_V1
    assert result["dcid"] == DCID
    assert result["scid"] == b""
    assert result["packet_number"] == 2
    assert result["client_hello"] == EXPECTED_CLIENT_HELLO


def test_extract_client_hello_matches_vector():
    keys = quic.derive_initial_keys(DCID)
    pkt = quic.parse_packets(PROTECTED)[0]
    assert quic.extract_client_hello(pkt, keys) == EXPECTED_CLIENT_HELLO


# ---------------------------------------------------------------------------
# End-to-end: QUIC -> tls -> ja4
# ---------------------------------------------------------------------------

def test_recovered_client_hello_feeds_tls_and_ja4():
    result = quic.client_hello_from_datagram(PROTECTED)
    hello = parse_client_hello(result["client_hello"])
    assert hello["sni"] == "example.com"
    assert hello["alpn"][0] == b"alpn"
    assert ja4(hello, proto="q").startswith("q13")


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------

def test_random_datagram_returns_none():
    assert quic.client_hello_from_datagram(bytes(range(256))) is None
    assert quic.client_hello_from_datagram(os.urandom(64)) is None


def test_truncated_initial_is_discarded_not_crashed():
    truncated = PROTECTED[:30]  # header parses, but the 16-byte sample is gone
    assert quic.client_hello_from_datagram(truncated) is None
    packets = quic.parse_packets(truncated)
    assert packets and packets[0]["packet_type"] == "initial"


def test_multiple_packets_in_one_datagram():
    packets = quic.parse_packets(PROTECTED + PROTECTED)
    assert len(packets) == 2
    assert all(p["packet_type"] == "initial" for p in packets)
    assert all(p["pn_offset"] == 18 for p in packets)
    assert packets[1]["dcid"] == DCID


def test_no_crypto_library_reports_plainly(monkeypatch):
    monkeypatch.setattr(quic, "HAVE_CRYPTO", False)
    # nothing decrypts, and nothing raises
    assert quic.client_hello_from_datagram(PROTECTED) is None
    # the header parse is independent of the crypto library
    packets = quic.parse_packets(PROTECTED)
    assert packets[0]["packet_type"] == "initial"
    assert packets[0]["dcid"] == DCID
    with pytest.raises(quic.QuicUnavailable):
        quic.decrypt_initial(packets[0], quic.derive_initial_keys(DCID))


# ---------------------------------------------------------------------------
# Varints and frames
# ---------------------------------------------------------------------------

def test_varint_widths():
    assert quic.read_varint(b"\x00", 0) == (0, 1)
    assert quic.read_varint(b"\x3f", 0) == (63, 1)
    assert quic.read_varint(b"\x7f", 0) is None  # 2-byte prefix, 1 byte present
    assert quic.read_varint(b"\x44\x9e", 0) == (1182, 2)
    assert quic.read_varint(b"\x40\x25", 0) == (37, 2)
    assert quic.read_varint(b"\x80\x00\x00\x01", 0) == (1, 4)
    assert quic.read_varint(b"\xc0\x00\x00\x00\x00\x00\x00\x00", 0) == (0, 8)
    assert quic.read_varint(b"", 0) is None
    assert quic.read_varint(b"\x40", 0) is None  # width 2, only 1 byte present


def test_crypto_frames_skips_padding_and_stops_on_unknown():
    frame = b"\x06\x00\x03abc"           # CRYPTO offset 0, length 3
    frames = quic.crypto_frames(b"\x00\x00" + frame)
    assert frames == [{"offset": 0, "data": b"abc"}]
    # an unknown frame type after a CRYPTO frame stops parsing cleanly
    assert quic.crypto_frames(frame + b"\x1c\x01") == [{"offset": 0, "data": b"abc"}]


def test_reassemble_crypto_out_of_order_and_overlap():
    frames = [{"offset": 3, "data": b"def"}, {"offset": 0, "data": b"abc"}]
    assert quic._reassemble_crypto(frames) == b"abcdef"
    overlapping = [{"offset": 0, "data": b"abc"}, {"offset": 2, "data": b"cdef"}]
    assert quic._reassemble_crypto(overlapping) == b"abcdef"

# ---------------------------------------------------- cross-packet reassembly

def _build_initial(dcid, packet_number, crypto_offset, crypto_data, pad_to=None):
    """Build a protected QUIC Initial carrying one CRYPTO frame.

    Written here so the reassembly can be tested with a ClientHello that does
    not fit in one packet -- which is what real traffic looks like, and what
    the RFC's single-packet vector does not cover.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    keys = quic.derive_initial_keys(dcid, quic.QUIC_V1)

    def varint(n):
        if n < 0x40:
            return bytes([n])
        if n < 0x4000:
            return (n | 0x4000).to_bytes(2, "big")
        if n < 0x40000000:
            return (n | 0x80000000).to_bytes(4, "big")
        return (n | 0xC000000000000000).to_bytes(8, "big")

    frame = b"\x06" + varint(crypto_offset) + varint(len(crypto_data)) + crypto_data
    scid = b""
    header = (b"\xc3" + b"\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid
              + bytes([len(scid)]) + scid)
    token_len = varint(0)
    payload = frame + (b"\x00" * max(0, (pad_to or 1200) - len(frame) - 4 - 16))
    pn_len = 4
    length = varint(pn_len + len(payload) + 16)
    header += token_len + length
    pn_offset = len(header)
    pn = packet_number.to_bytes(pn_len, "big")
    aad = header + pn
    nonce = bytes(a ^ b for a, b in zip(keys["iv"], packet_number.to_bytes(12, "big"), strict=True))
    ct = AESGCM(keys["key"]).encrypt(nonce, payload, aad)
    packet = bytearray(aad + ct)

    # header protection
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    sample = bytes(packet[pn_offset + 4:pn_offset + 20])
    mask = Cipher(algorithms.AES(keys["hp"]), modes.ECB()).encryptor().update(sample)
    packet[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        packet[pn_offset + i] ^= mask[1 + i]
    return bytes(packet)


def test_crypto_assembler_reassembles_a_split_client_hello():
    """A ClientHello split across two Initials must still fingerprint.

    This is the case the RFC vector does not cover and real traffic always
    does: on an ordinary machine a 1746-byte ClientHello arrived as 1211 bytes
    in one Initial and the remaining 535 in the next.
    """
    pytest.importorskip("cryptography")
    dcid = bytes.fromhex("8394c8f03e515708")
    hello = EXPECTED_CLIENT_HELLO
    cut = len(hello) // 2
    first = _build_initial(dcid, 1, 0, hello[:cut])
    second = _build_initial(dcid, 2, cut, hello[cut:])

    assembler = quic.CryptoAssembler()
    assert assembler.feed(first) is None, "half a ClientHello is not a ClientHello"
    got = assembler.feed(second)
    assert got is not None, "the second Initial must complete the handshake"
    assert got["client_hello"] == hello
    assert got["dcid"] == dcid


def test_crypto_assembler_ignores_unrelated_offsets():
    """A frame whose offset does not join the stream must not be spliced in."""
    pytest.importorskip("cryptography")
    dcid = bytes.fromhex("0011223344556677")
    hello = EXPECTED_CLIENT_HELLO
    assembler = quic.CryptoAssembler()
    # an unrelated chunk far from the start must not make a ClientHello appear
    stray = _build_initial(dcid, 1, 9000, b"\xde\xad\xbe\xef" * 40)
    assert assembler.feed(stray) is None
    # and the real stream still assembles afterwards
    assert assembler.feed(_build_initial(dcid, 2, 0, hello)) is not None


def test_crypto_assembler_returns_a_shaped_dict():
    pytest.importorskip("cryptography")
    dcid = bytes.fromhex("aabbccddeeff0011")
    assembler = quic.CryptoAssembler()
    got = assembler.feed(_build_initial(dcid, 7, 0, EXPECTED_CLIENT_HELLO))
    assert got is not None
    for key in ("version", "dcid", "scid", "client_hello", "packet_number"):
        assert key in got, "missing %s" % key
    assert got["version"] == quic.QUIC_V1
    assert got["packet_number"] == 7


def test_crypto_assembler_gives_up_on_a_hopeless_stream():
    """A stream that never becomes a ClientHello must not grow without bound."""
    pytest.importorskip("cryptography")
    dcid = bytes.fromhex("0102030405060708")
    assembler = quic.CryptoAssembler(max_bytes=4096)
    junk = b"\x17" * 1024
    for i in range(12):
        assembler.feed(_build_initial(dcid, i + 1, i * 1024, junk))
    assert assembler.dropped >= 1, "an unbounded stream must be dropped, not kept"


def test_crypto_assembler_survives_a_non_quic_datagram():
    assembler = quic.CryptoAssembler()
    assert assembler.feed(b"") is None
    assert assembler.feed(b"\x00\x01\x02 not quic") is None
    assert assembler.feed(b"\xff" * 200) is None
