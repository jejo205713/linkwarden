"""LinkWarden Flask app — hardened entry point."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

from bert_engine import analyze_message
from geo_lookup import lookup_geo
from predictor import analyze_url
from storage import list_reports, report_count, save_report


MAX_URL_LEN = 2048
MAX_MESSAGE_LEN = 8192

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static",
)

CORS(app)

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("linkwarden")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/report")
def report_page():
    return render_template("report.html")


@app.route("/bert")
def bert_page():
    return render_template("bert.html")


@app.route("/favicon.ico")
def favicon():
    try:
        return app.send_static_file("favicon.ico")
    except Exception:
        return ("", 204)


def _payload(req) -> dict:
    data = req.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _err(message: str, code: int = 400):
    return jsonify({"error": message}), code


def _str(value, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:
        return default


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = _payload(request)
    url = _str(data.get("url")).strip()

    if not url:
        return _err("No URL provided")
    if len(url) > MAX_URL_LEN:
        return _err(f"URL exceeds {MAX_URL_LEN} characters")
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url

    try:
        result = analyze_url(url)
    except Exception as exc:
        log.exception("analyze_url failed")
        return _err(f"Internal analysis failure: {type(exc).__name__}", 500)

    return jsonify(result), 200


@app.route("/api/analyze-message", methods=["POST"])
def analyze_msg():
    data = _payload(request)
    message = _str(data.get("message")).strip()

    if not message:
        return _err("No message provided")
    if len(message) > MAX_MESSAGE_LEN:
        return _err(f"Message exceeds {MAX_MESSAGE_LEN} characters")

    try:
        return jsonify(analyze_message(message)), 200
    except Exception:
        log.exception("analyze_message failed")
        return _err("Message analysis failed", 500)


@app.route("/api/geo", methods=["POST"])
def geo():
    data = _payload(request)
    url = _str(data.get("url")).strip()
    if not url:
        return _err("No URL provided")
    if len(url) > MAX_URL_LEN:
        return _err(f"URL exceeds {MAX_URL_LEN} characters")
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url

    try:
        return jsonify(lookup_geo(url)), 200
    except Exception:
        log.exception("geo lookup failed")
        return jsonify({"ok": False, "error": "geo lookup failed"}), 200


@app.route("/api/report", methods=["POST"])
def submit_report():
    data = _payload(request)

    email = _str(data.get("email")).strip()
    phishing_url = _str(data.get("phishing_url")).strip()
    if not email or not phishing_url:
        return _err("email and phishing_url are required")
    if len(phishing_url) > MAX_URL_LEN:
        return _err(f"phishing_url exceeds {MAX_URL_LEN} characters")

    indicators = data.get("indicators", [])
    if not isinstance(indicators, list):
        indicators = []

    payload = {
        "name": _str(data.get("name")).strip()[:200],
        "email": email[:320],
        "phishing_url": phishing_url[:MAX_URL_LEN],
        "incident_date": _str(data.get("incident_date")).strip()[:32],
        "financial_loss": _str(data.get("financial_loss") or "None").strip()[:64],
        "details": _str(data.get("details")).strip()[:5000],
        "scan_result": _str(data.get("scan_result")).strip()[:32],
        "risk_level": _str(data.get("risk_level")).strip()[:32],
        "indicators": [_str(i)[:200] for i in indicators[:50]],
    }

    try:
        record = save_report(payload)
    except Exception:
        log.exception("save_report failed")
        return _err("Could not store report", 500)

    log.info("[REPORT] %s -> %s @ %s", record["email"], record["phishing_url"], record["timestamp"])

    return jsonify({
        "status": "success",
        "id": record.get("id"),
        "timestamp": record["timestamp"],
        "message": "Report successfully logged for cyber authorities.",
    }), 200


@app.route("/api/reports", methods=["GET"])
def fetch_reports():
    try:
        limit = int(request.args.get("limit", "50"))
    except ValueError:
        limit = 50
    try:
        return jsonify({
            "count": report_count(),
            "reports": list_reports(limit=limit),
        }), 200
    except Exception:
        log.exception("list_reports failed")
        return _err("Could not fetch reports", 500)


@app.errorhandler(404)
def _not_found(_):
    if request.path.startswith("/api/"):
        return _err("Not found", 404)
    return ("Not found", 404)


@app.errorhandler(405)
def _method_not_allowed(_):
    return _err("Method not allowed", 405)


if __name__ == "__main__":
    log.info("LinkWarden backend starting on :5000")
    app.run(host="0.0.0.0", port=5000, debug=False)