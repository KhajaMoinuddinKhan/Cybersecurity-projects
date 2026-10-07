import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src import rules  # noqa: E402
from src.rules import (  # noqa: E402
    KNOWN_FP_FAMILY,
    ech_obscured,
    evaluate,
    first_seen,
    fp_rotation,
    known_bad,
    monoculture,
    os_mismatch,
    ua_mismatch,
)


def ev(**kw):
    base = {
        "ts": 1000.0,
        "src_ip": "10.0.0.1",
        "dst_ip": "1.1.1.1",
        "src_port": 50000,
        "dst_port": 443,
        "sni": "example.com",
        "alpn": "h2",
        "user_agent": None,
        "fingerprints": {},
        "category": None,
        "intel_name": None,
    }
    base.update(kw)
    return base


def browser_ja3():
    for value, family in KNOWN_FP_FAMILY["ja3"].items():
        if family == "browser":
            return value
    raise AssertionError("no browser JA3 in the built-in table")


def only(alerts, rule):
    return [a for a in alerts if a["rule"] == rule]


# --------------------------------------------------------------- known_bad
def test_known_bad_fires_malware():
    e = ev(category="malware", intel_name="Emotet",
           fingerprints={"ja3": "6734f37431670b3ab4292b8f60f29984"})
    alerts = known_bad(e, {})
    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule"] == "known_bad"
    assert a["severity"] == "critical"
    assert a["title"] == "known-bad fingerprint"
    assert "ja3" in a["detail"]
    assert "6734f37431670b3ab4292b8f60f29984" in a["detail"]
    assert "Emotet" in a["detail"]


def test_known_bad_fires_c2():
    e = ev(category="c2", intel_name="CobaltStrike", fingerprints={"ja4": "t13dXYZ"})
    alerts = known_bad(e, {})
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "critical"
    assert "t13dXYZ" in alerts[0]["detail"]


def test_known_bad_silent_benign_or_missing():
    assert known_bad(ev(category="benign"), {}) == []
    assert known_bad(ev(category="tool"), {}) == []
    assert known_bad(ev(category=None), {}) == []


def test_known_bad_uses_corpus_to_name_kind():
    class FakeCorpus:
        def match(self, kind, value):
            if kind == "ja4" and value == "t13dMATCH":
                return {"category": "malware", "name": "FakeLoader"}
            return None

    e = ev(category="malware", fingerprints={"ja3": "aaaa", "ja4": "t13dMATCH"})
    alerts = known_bad(e, {"corpus": FakeCorpus()})
    assert len(alerts) == 1
    d = alerts[0]["detail"]
    assert "ja4" in d and "t13dMATCH" in d and "FakeLoader" in d


# -------------------------------------------------------------- ua_mismatch
def test_ua_mismatch_fires_with_builtin_table():
    e = ev(user_agent="curl/8.4.0", fingerprints={"ja3": browser_ja3()})
    alerts = ua_mismatch(e, {})
    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule"] == "ua_mismatch"
    assert a["severity"] == "medium"
    assert a["title"] == "the user-agent is lying"
    assert "curl" in a["detail"]


def test_ua_mismatch_fires_with_override_table():
    e = ev(user_agent="python-requests/2.31.0", fingerprints={"ja4": "t13dPY"})
    alerts = ua_mismatch(e, {"fp_family": {"ja4": {"t13dPY": "browser"}}})
    assert len(alerts) == 1
    assert "python-requests" in alerts[0]["detail"]


def test_ua_mismatch_silent_when_families_agree():
    e = ev(user_agent="Mozilla/5.0 (Windows NT 10.0) AppleWebKit Chrome/120 Safari/537",
           fingerprints={"ja3": browser_ja3()})
    assert ua_mismatch(e, {}) == []


def test_ua_mismatch_silent_when_fingerprint_unknown():
    # unknown hash -> cannot establish family -> must NOT guess
    e = ev(user_agent="curl/8.4.0", fingerprints={"ja3": "deadbeefdeadbeefdeadbeefdeadbeef"})
    assert ua_mismatch(e, {}) == []
    e2 = ev(user_agent="Go-http-client/1.1", fingerprints={"ja4": "t13dUNKNOWN"})
    assert ua_mismatch(e2, {}) == []


def test_ua_mismatch_silent_when_ua_unknown():
    e = ev(user_agent="TotallyUnknownAgent/9", fingerprints={"ja3": browser_ja3()})
    assert ua_mismatch(e, {}) == []
    e2 = ev(user_agent=None, fingerprints={"ja3": browser_ja3()})
    assert ua_mismatch(e2, {}) == []


# -------------------------------------------------------------- os_mismatch
def test_os_mismatch_fires():
    e = ev(user_agent="Mozilla/5.0 (X11; Linux x86_64) Gecko Firefox/121",
           fingerprints={"ja3": "aa11bb22cc33dd44ee55ff6677889900"})
    alerts = os_mismatch(e, {"os_by_ja3": {"aa11bb22cc33dd44ee55ff6677889900": "windows"}})
    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule"] == "os_mismatch"
    assert a["severity"] == "medium"
    assert a["title"] == "the stack betrays the os"
    assert "aa11bb22cc33dd44ee55ff6677889900" in a["detail"]
    assert "windows" in a["detail"] and "linux" in a["detail"]


def test_os_mismatch_silent_when_agreeing():
    e = ev(user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/120",
           fingerprints={"ja3": "aa11"})
    assert os_mismatch(e, {"os_by_ja3": {"aa11": "windows"}}) == []


def test_os_mismatch_silent_when_ja3_unknown():
    e = ev(user_agent="Mozilla/5.0 (X11; Linux) Firefox/121",
           fingerprints={"ja3": "unknownja3"})
    assert os_mismatch(e, {"os_by_ja3": {"aa11": "windows"}}) == []
    # no map at all
    e2 = ev(user_agent="Mozilla/5.0 (X11; Linux) Firefox/121",
            fingerprints={"ja3": "aa11"})
    assert os_mismatch(e2, {}) == []


# --------------------------------------------------------------- first_seen
def test_first_seen_fires():
    e = ev(fingerprints={"ja3": "abc"})
    alerts = first_seen(e, {"seen_before": lambda kind, value: False})
    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule"] == "first_seen"
    assert a["severity"] == "info"
    assert a["title"] == "first sighting"
    assert "ja3" in a["detail"] and "abc" in a["detail"]


def test_first_seen_silent_when_seen():
    e = ev(fingerprints={"ja3": "abc"})
    assert first_seen(e, {"seen_before": lambda kind, value: True}) == []


def test_first_seen_stateful_and_multiple_kinds():
    seen = set()

    def sb(kind, value):
        if (kind, value) in seen:
            return True
        seen.add((kind, value))
        return False

    e = ev(fingerprints={"ja3": "j3", "ja4": "j4"})
    first = first_seen(e, {"seen_before": sb})
    assert len(first) == 2
    assert first_seen(e, {"seen_before": sb}) == []


def test_first_seen_silent_without_seen_before():
    e = ev(fingerprints={"ja3": "abc"})
    assert first_seen(e, {}) == []


# --------------------------------------------------------------- fp_rotation
def _hist(src, sni, ts, ja4):
    return {"ts": ts, "src_ip": src, "sni": sni, "fingerprints": {"ja4": ja4}}


def test_fp_rotation_fires_with_three_distinct_ja4():
    cur = ev(ts=1000.0, src_ip="10.0.0.9", sni="bank.com", fingerprints={"ja4": "c"})
    hist = [_hist("10.0.0.9", "bank.com", 995.0, "a"),
            _hist("10.0.0.9", "bank.com", 998.0, "b")]
    alerts = fp_rotation(cur, {"history": hist, "window": 300})
    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule"] == "fp_rotation"
    assert a["severity"] == "high"
    assert a["title"] == "identity rotation"
    assert "10.0.0.9" in a["detail"] and "bank.com" in a["detail"]


def test_fp_rotation_silent_with_only_two_ja4():
    cur = ev(ts=1000.0, src_ip="10.0.0.9", sni="bank.com", fingerprints={"ja4": "b"})
    hist = [_hist("10.0.0.9", "bank.com", 995.0, "a")]
    assert fp_rotation(cur, {"history": hist, "window": 300}) == []


def test_fp_rotation_silent_for_different_sni():
    cur = ev(ts=1000.0, src_ip="10.0.0.9", sni="bank.com", fingerprints={"ja4": "c"})
    hist = [_hist("10.0.0.9", "other.com", 995.0, "a"),
            _hist("10.0.0.9", "other.com", 998.0, "b")]
    assert fp_rotation(cur, {"history": hist, "window": 300}) == []


def test_fp_rotation_silent_outside_window():
    cur = ev(ts=1000.0, src_ip="10.0.0.9", sni="bank.com", fingerprints={"ja4": "c"})
    hist = [_hist("10.0.0.9", "bank.com", 100.0, "a"),
            _hist("10.0.0.9", "bank.com", 101.0, "b")]
    assert fp_rotation(cur, {"history": hist, "window": 300}) == []


def test_fp_rotation_silent_without_sni():
    cur = ev(ts=1000.0, src_ip="10.0.0.9", sni=None, fingerprints={"ja4": "c"})
    hist = [_hist("10.0.0.9", None, 995.0, "a"), _hist("10.0.0.9", None, 998.0, "b")]
    assert fp_rotation(cur, {"history": hist, "window": 300}) == []


# -------------------------------------------------------------- monoculture
def _ip_hist(ip, ts, ja4):
    return {"ts": ts, "src_ip": ip, "sni": "cdn.com", "fingerprints": {"ja4": ja4}}


def test_monoculture_fires_with_ten_distinct_ips():
    cur = ev(ts=1000.0, src_ip="10.0.0.100", fingerprints={"ja4": "shared"})
    hist = [_ip_hist("10.0.0.%d" % i, 990.0, "shared") for i in range(1, 10)]  # 9 + cur = 10
    alerts = monoculture(cur, {"history": hist, "window": 300})
    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule"] == "monoculture"
    assert a["severity"] == "medium"
    assert a["title"] == "one toolkit, many hosts"
    assert "shared" in a["detail"]


def test_monoculture_silent_with_nine_distinct_ips():
    cur = ev(ts=1000.0, src_ip="10.0.0.100", fingerprints={"ja4": "shared"})
    hist = [_ip_hist("10.0.0.%d" % i, 990.0, "shared") for i in range(1, 9)]  # 8 + cur = 9
    assert monoculture(cur, {"history": hist, "window": 300}) == []


def test_monoculture_silent_for_distinct_values():
    cur = ev(ts=1000.0, src_ip="10.0.0.100", fingerprints={"ja4": "shared"})
    hist = [_ip_hist("10.0.0.%d" % i, 990.0, "other%d" % i) for i in range(1, 15)]
    assert monoculture(cur, {"history": hist, "window": 300}) == []


# ------------------------------------------------------------------ evaluate
def test_evaluate_aggregates_rules():
    e = ev(category="c2", intel_name="X", user_agent="curl/8.4.0",
           fingerprints={"ja3": browser_ja3()})
    alerts = evaluate(e, {"seen_before": lambda kind, value: False})
    names = {a["rule"] for a in alerts}
    assert "known_bad" in names
    assert "ua_mismatch" in names
    assert "first_seen" in names


def test_evaluate_never_raises_on_malformed_event():
    assert evaluate(None, {}) == []
    assert evaluate({}, {}) == []
    assert evaluate("not-a-dict", {}) == []
    assert evaluate({"fingerprints": None}, {"seen_before": lambda k, v: (_ for _ in ()).throw(ValueError())}) == []
    assert evaluate({"ts": "x", "src_ip": None, "fingerprints": "nope"}, {}) == []
    assert evaluate({"fingerprints": {"ja3": 123, "ja4": None}}, {}) == []
    # ctx of the wrong type must also be tolerated
    assert evaluate(ev(), None) == []
    assert evaluate(ev(), "ctx") == []


def test_all_rules_are_separate_callables():
    for name in ("known_bad", "ua_mismatch", "os_mismatch", "first_seen",
                 "fp_rotation", "monoculture", "ech_obscured"):
        assert callable(getattr(rules, name))
    assert len(rules.RULES) == 7


def test_every_alert_has_the_four_contract_keys():
    e = ev(category="malware", intel_name="Emotet", user_agent="curl/8",
           fingerprints={"ja3": browser_ja3()})
    alerts = evaluate(e, {"seen_before": lambda k, v: False})
    assert alerts
    for a in alerts:
        assert set(a) == {"rule", "severity", "title", "detail"}


# -------------------------------------------------------------- ech_obscured
def test_ech_obscured_fires_on_ech_event():
    e = ev(ech=True, sni="cover.example",
           fingerprints={"ja4": "t13dXYZ"})
    alerts = ech_obscured(e, {})
    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule"] == "ech_obscured"
    assert a["severity"] == "info"
    assert a["title"] == "an ECH offer may hide the handshake"
    assert "cover.example" in a["detail"]
    assert "outer" in a["detail"].lower()


def test_ech_obscured_silent_without_flag():
    assert ech_obscured(ev(fingerprints={"ja4": "t13dXYZ"}), {}) == []
    assert ech_obscured(ev(ech=False, fingerprints={"ja4": "x"}), {}) == []
    assert ech_obscured(ev(ech=None), {}) == []


def test_ech_obscured_malformed_event_does_not_raise():
    # ech true but no fingerprints / no sni at all
    ech_obscured({"ech": True}, {})
    ech_obscured(ev(ech=True, sni=None, fingerprints={}), {})
    ech_obscured({"ech": True, "sni": 123}, {})
    assert ech_obscured(None, {}) == []
    assert ech_obscured("not-a-dict", {}) == []
    # evaluate must also stay quiet-safe
    evaluate({"ech": True}, {})


def test_ech_obscured_does_not_fire_without_ech_in_evaluate():
    e = ev(sni="real.example.com", fingerprints={"ja4": "t13dXYZ"})
    names = {a["rule"] for a in evaluate(e, {})}
    assert "ech_obscured" not in names
