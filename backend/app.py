from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from predictor import analyze_url
from whois_lookup import get_whois_info
from dns_lookup import get_dns_info
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
    """Serve main dashboard UI"""
    return render_template('index.html')


@app.route('/report')
def report_page():
    """Serve cybercrime reporting page"""
    return render_template('report.html')


# ==========================================
# API: URL Analysis
# ==========================================

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Analyze URL using ML + WHOIS + DNS intelligence"""

    data = request.get_json()

    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data['url'].strip()

    # Normalize URL
    if not url.startswith('http'):
        url = 'http://' + url

    try:
        # 1️⃣ Run ML model
        analysis = analyze_url(url)

        # 2️⃣ Fetch WHOIS info
        whois_info = get_whois_info(url)

        # 3️⃣ Fetch DNS info (optional but useful)
        dns_info = get_dns_info(url)

        # 4️⃣ Build response for frontend
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
# API: Cybercrime Report
# ==========================================

@app.route('/api/report', methods=['POST'])
def submit_report():
    """Handle cybercrime incident reports"""

    data = request.get_json()

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