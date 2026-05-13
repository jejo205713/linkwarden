"""Incident reports must be persisted (JSONL when the env override is set)."""
import json
import os
import sys
import types


def test_report_appends_to_jsonl(tmp_path, monkeypatch):
    fake_reports = tmp_path / "reports.jsonl"
    monkeypatch.setenv("LINKWARDEN_REPORTS_FILE", str(fake_reports))

    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

    for mod in ("app", "bert_engine", "geo_lookup", "storage", "predictor"):
        sys.modules.pop(mod, None)

    fake_bert = types.ModuleType("bert_engine")
    fake_bert.analyze_message = lambda msg: {"status": "SAFE", "scam_probability": 0.0, "model_available": False}
    sys.modules["bert_engine"] = fake_bert

    fake_geo = types.ModuleType("geo_lookup")
    fake_geo.lookup_geo = lambda url: {"ok": False}
    sys.modules["geo_lookup"] = fake_geo

    import app as app_module

    client = app_module.app.test_client()
    response = client.post("/api/report", json={
        "name": "Test User",
        "email": "test@example.com",
        "phishing_url": "http://sbi-fake.xyz",
        "financial_loss": "Money Lost",
        "details": "Lost 5000",
        "indicators": ["INSECURE_HTTP", "SUSPICIOUS_TLD"],
    })

    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "success"
    assert "timestamp" in body

    assert fake_reports.exists()
    lines = fake_reports.read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["email"] == "test@example.com"
    assert record["phishing_url"] == "http://sbi-fake.xyz"
    assert "timestamp" in record


def test_reports_retrieval_endpoint(tmp_path, monkeypatch):
    fake_reports = tmp_path / "reports.jsonl"
    monkeypatch.setenv("LINKWARDEN_REPORTS_FILE", str(fake_reports))

    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))
    for mod in ("app", "bert_engine", "geo_lookup", "storage", "predictor"):
        sys.modules.pop(mod, None)

    fake_bert = types.ModuleType("bert_engine")
    fake_bert.analyze_message = lambda msg: {"status": "SAFE"}
    sys.modules["bert_engine"] = fake_bert

    fake_geo = types.ModuleType("geo_lookup")
    fake_geo.lookup_geo = lambda url: {"ok": False}
    sys.modules["geo_lookup"] = fake_geo

    import app as app_module
    client = app_module.app.test_client()

    for i in range(3):
        client.post("/api/report", json={
            "email": f"u{i}@example.com",
            "phishing_url": f"http://example{i}.xyz",
        })

    resp = client.get("/api/reports?limit=10")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["count"] == 3
    assert len(body["reports"]) == 3
    # Newest-first ordering
    assert body["reports"][0]["email"] == "u2@example.com"
