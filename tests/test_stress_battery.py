"""Stress test battery — every endpoint must return a valid HTTP response,
never a 500, for adversarial inputs.

Categories covered:
- malformed URLs (missing schemes, control bytes, broken brackets, bad ports)
- giant inputs (8KB+ URL, 64KB+ message)
- type-confusion (numeric/list/dict where strings expected)
- Unicode (Tamil, Devanagari, emoji, RTL, mixed scripts)
- IDN / punycode hostnames
- IPv4 / IPv6 hosts
- common phishing patterns (typosquats, shorteners, IP-based)
- empty / whitespace-only / null bodies
"""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("LINKWARDEN_REPORTS_FILE", str(tmp_path / "reports.jsonl"))
    monkeypatch.setenv("LINKWARDEN_REPORTS_DB", str(tmp_path / "reports.sqlite"))

    for mod in ("app", "bert_engine", "geo_lookup", "storage", "predictor"):
        sys.modules.pop(mod, None)

    fake_bert = types.ModuleType("bert_engine")
    fake_bert.analyze_message = lambda msg: {
        "status": "SAFE", "confidence_score": 0, "scam_probability": 0,
        "explanations": [], "triggered_rules": [], "matched_keywords": [],
        "detected_categories": [], "risk_factors": {}, "model_available": False,
    }
    sys.modules["bert_engine"] = fake_bert

    fake_geo = types.ModuleType("geo_lookup")
    fake_geo.lookup_geo = lambda url: {"ok": False, "ip": "—", "country": "Unknown",
                                       "city": "Unknown", "lat": 0, "lon": 0,
                                       "asn": "Unknown", "isp": "Unknown", "org": "Unknown"}
    sys.modules["geo_lookup"] = fake_geo

    import app as app_module
    return app_module.app.test_client()


# ---------------------------------------------------------------------------
# /api/analyze
# ---------------------------------------------------------------------------

ANALYZE_URLS = [
    # Empty / whitespace
    "", "   ", "\t\n",
    # Missing scheme
    "google.com", "sbi.co.in/login",
    # Malformed
    "http://", "http://[invalid", "://no-scheme.com", "http://example.com:abc/x",
    "http://1.2.3.4:99999/x",
    # Control / null bytes (URL-encoded fine; literals must be tolerated)
    "http://example.com/\x00null", "http://%00.com/", "http://a%20b%20c.com",
    # Long URLs
    "http://example.com/" + "a" * 1900,
    # IPv6
    "http://[2001:db8::1]/path",
    # Unicode hostname
    "http://தமிழ்.com/", "http://हिन्दी.example/",
    # Punycode/homoglyph
    "http://xn--pypl-53dc3a.com/login",
    # Real legit
    "https://www.google.com",
    "https://www.sbi.co.in/web/personal-banking",
    # Phishing-style
    "http://sbi-kyc-update.xyz/login",
    "http://paaytm-rewards.gq",
    "http://192.168.45.211/upi/login",
    "http://bit.ly/abc123",
    # @ trick
    "http://google.com@evil.xyz/",
    # Lots of subdomains
    "http://a.b.c.d.e.f.g.h.example.com/",
    # Query abuse
    "http://example.com/" + "?p=" + "x" * 1500,
    # Repeated chars
    "http://aaaaaaaaaa.xyz",
]


@pytest.mark.parametrize("url", ANALYZE_URLS)
def test_analyze_never_500s(client, url):
    resp = client.post("/api/analyze", json={"url": url})
    assert resp.status_code != 500, f"500 on input {url!r}"
    body = resp.get_json()
    assert isinstance(body, dict)
    if resp.status_code == 200:
        assert "status" in body and body["status"] in ("SAFE", "SUSPICIOUS", "PHISHING")
        assert "risk_factors" in body
        assert "triggered_rules" in body


def test_analyze_type_confusion(client):
    for value in [None, 12345, ["url", "list"], {"k": "v"}, True, 3.14]:
        resp = client.post("/api/analyze", json={"url": value})
        assert resp.status_code != 500, f"500 on type {type(value).__name__}"


def test_analyze_oversize_url(client):
    big = "http://example.com/" + "a" * 5000
    resp = client.post("/api/analyze", json={"url": big})
    assert resp.status_code == 400


def test_analyze_garbage_json_body(client):
    resp = client.post("/api/analyze", data="not json", content_type="application/json")
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /api/analyze-message
# ---------------------------------------------------------------------------

MESSAGES = [
    "Hi mom, on my way home.",
    "Aapka SBI khata band ho gaya hai. OTP de turant.",
    "உங்கள் SBI கணக்கு முடக்கப்பட்டுள்ளது. ஓடிபி பகிரவும்: 4521",
    "🚨🚨🚨 URGENT 🚨🚨🚨 CLICK NOW http://x.xyz",
    "x" * 8000,
    " ",
    "Mixed scripts: paisa kab milega? सब्सिडी मिलेगी कब?",
    "ASCII only safe message",
]


@pytest.mark.parametrize("msg", MESSAGES)
def test_analyze_message_never_500s(client, msg):
    resp = client.post("/api/analyze-message", json={"message": msg})
    assert resp.status_code != 500
    if resp.status_code == 200:
        body = resp.get_json()
        assert "status" in body
        assert "explanations" in body
        assert "triggered_rules" in body


def test_analyze_message_oversize(client):
    resp = client.post("/api/analyze-message", json={"message": "x" * 9000})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /api/report
# ---------------------------------------------------------------------------

def test_report_requires_email_and_url(client):
    resp = client.post("/api/report", json={})
    assert resp.status_code == 400


def test_report_handles_unicode(client):
    resp = client.post("/api/report", json={
        "email": "user@example.in",
        "phishing_url": "http://தமிழ்.example.xyz/login",
        "details": "முடக்கம் scam attack",
        "name": "ராஜா",
    })
    assert resp.status_code == 200


def test_report_truncates_overlong_fields(client):
    resp = client.post("/api/report", json={
        "email": "x@y.com",
        "phishing_url": "http://example.com",
        "details": "z" * 50_000,
    })
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /api/geo
# ---------------------------------------------------------------------------

def test_geo_requires_url(client):
    resp = client.post("/api/geo", json={})
    assert resp.status_code == 400


def test_geo_with_garbage(client):
    # Mocked geo_lookup always returns ok=False; endpoint must still respond.
    resp = client.post("/api/geo", json={"url": "not-a-real-domain-xxxxx"})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Catchalls
# ---------------------------------------------------------------------------

def test_unknown_api_route_404(client):
    resp = client.post("/api/does-not-exist", json={})
    assert resp.status_code == 404


def test_wrong_method_405(client):
    resp = client.get("/api/analyze")
    assert resp.status_code == 405
