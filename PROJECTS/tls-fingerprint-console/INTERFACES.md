# Interface contract — tls-fingerprint-console

Every module is written against these signatures. Do not change a signature
without changing this file.

## src/pcap.py
    read_pcap(path: str) -> list[dict]
        # {ts: float, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        #  protocol: "tcp"|"udp", flags: str, seq: int, ack: int,
        #  window: int, tcp_options: list[int], mss: int|None,
        #  window_scale: int|None, payload: bytes}
    reassemble_streams(packets: list[dict]) -> list[dict]
        # {src_ip, dst_ip, src_port, dst_port, payload: bytes}  payload = all bytes
        # for that direction, in order

## src/tls.py   (parses a byte stream, no packet framing)
    iter_tls_records(payload: bytes) -> list[dict]
        # {record_type: int, version: int, body: bytes}
    parse_client_hello(body: bytes) -> dict
        # {version: int, session_id: bytes, ciphers: list[int],
        #  extensions: list[int], sni: str|None, alpn: list[bytes],
        #  curves: list[int], point_formats: list[int], sig_algs: list[int],
        #  supported_versions: list[int], grease: list[int]}
        #   ciphers/extensions/curves/point_formats/sig_algs are in WIRE ORDER
        #   and INCLUDE grease; the fingerprint modules strip grease themselves.
    parse_server_hello(body: bytes) -> dict
        # {version: int, cipher: int, extensions: list[int], alpn: bytes|None}
    parse_certificate_message(body: bytes) -> list[bytes]
        # list of DER-encoded certificates
    parse_tcp_syn(packet: dict) -> dict
        # {window: int, options: list[int], mss: int|None, window_scale: int|None}
    parse_http_request(payload: bytes) -> dict
        # {method: str, version: str, headers: list[tuple[str,str]],
        #  cookie: str|None, referer: str|None, language: str|None,
        #  header_count: int}

## src/ja3.py
    ja3(hello: dict) -> str          # 32-char md5
    ja3_raw(hello: dict) -> str      # the pre-hash string
    ja3s(hello: dict) -> str
    ja3s_raw(hello: dict) -> str

## src/ja4.py
    ja4(hello: dict, proto: str = "t") -> str
    ja4_r(hello: dict, proto: str = "t") -> str
    ja4s(hello: dict, proto: str = "t") -> str
    ja4x(cert_der: bytes) -> str
    ja4t(syn: dict) -> str
    ja4h(req: dict) -> str

## src/corpus.py
    load_corpus(dir: str) -> Corpus
    Corpus.match(kind: str, value: str) -> Entry | None
    Corpus.entries() -> list[Entry]
    Corpus.stats() -> dict   # {"sources":[...], "by_category":[...], "total":int}
    # Entry: {kind, value, category, name, source, license}

## src/rules.py
    evaluate(event: dict, ctx: dict) -> list[dict]
    # returns alerts {rule, severity, title, detail}
    # rules: known_bad, ua_mismatch, os_mismatch, first_seen, fp_rotation, monoculture

## src/store.py
    Store(path)   .add_event(dict) .add_alert(dict) .events() .alerts()
                  .fingerprints() .stats() .seen_before(kind, value) .close()

## src/app.py
    create_app(store, corpus) -> Flask
    routes: /  /api/health  /api/stats  /api/alerts  /api/events
            /api/intel  /api/intel/search  /api/scope  /api/export
