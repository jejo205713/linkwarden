from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from predictor import analyze_url
from whois_lookup import get_whois_info
from dns_lookup import get_dns_info
from bert_engine import analyze_message
import os

app = Flask(
    __name__,
    template_folder='../frontend/templates',
    static_folder='../frontend/static'
)

CORS(app)

# ==========================================
# Frontend Routes
# ==========================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/report')
def report_page():
    return render_template('report.html')


@app.route('/bert')
def bert_page():
    return render_template('bert.html')


@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.ico')


# ==========================================
# API: URL Analysis
# ==========================================

@app.route('/api/analyze', methods=['POST'])
def analyze():

    data = request.get_json(silent=True)

    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data['url'].strip()

    if not url.startswith('http'):
        url = 'http://' + url

    try:
        analysis = analyze_url(url)

        whois_info = get_whois_info(url)

        dns_info = get_dns_info(url)

        response = {
            "status": analysis.get("status", "SAFE"),
            "confidence_score": analysis.get("confidence_score", 0),
            "expanded_url": analysis.get("expanded_url", url),
            "redirect_count": analysis.get("redirect_count", 0),

            "domain_age_days": whois_info.get("age_days", "Unknown"),
            "registrar": whois_info.get("registrar", "Unknown"),

            "dns_records": dns_info.get("num_a", 0),

            "reasons": analysis.get("reasons", [])
        }

        return jsonify(response), 200

    except Exception as e:
        print(f"ERROR: {str(e)}")

        return jsonify({
            "error": "Internal Analysis Engine Failure"
        }), 500


# ==========================================
# API: Message Scam Detection
# ==========================================

@app.route('/api/analyze-message', methods=['POST'])
def analyze_msg():

    data = request.get_json(silent=True)
    msg = data.get('message', '')

    if not msg:
        return jsonify({"error": "No message"}), 400

    try:
        result = analyze_message(msg)
        return jsonify(result), 200

    except Exception as e:
        print(f"BERT ERROR: {str(e)}")
        return jsonify({"error": "Message analysis failed"}), 500


# ==========================================
# API: Cybercrime Report
# ==========================================

@app.route('/api/report', methods=['POST'])
def submit_report():

    data = request.get_json(silent=True)

    print("\n" + "="*50)
    print("🚨 NEW CYBERCRIME INCIDENT REPORTED 🚨")
    print(f"Victim Name:     {data.get('name', 'Anonymous')}")
    print(f"Contact Email:   {data.get('email', 'N/A')}")
    print(f"Phishing URL:    {data.get('phishing_url', 'N/A')}")
    print(f"Financial Loss:  {data.get('financial_loss', 'None')}")
    print(f"Incident Details:{data.get('details', 'None')}")
    print("="*50 + "\n")

    return jsonify({
        "status": "success",
        "message": "Report successfully logged for cyber authorities."
    }), 200


# ==========================================
# Server Entry
# ==========================================

if __name__ == '__main__':
    print("🛡️ SafeLink AI Backend Starting...")
    app.run(host='0.0.0.0', port=5000, debug=True)