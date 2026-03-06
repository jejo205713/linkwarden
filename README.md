# 🛡️ LinkWarden AI  
### Intelligent Phishing Detection & Cyber Safety Platform

LinkWarden AI is a machine learning–powered cybersecurity platform designed to **detect phishing URLs and malicious links in real time**. The system analyzes URLs using multiple signals such as **URL structure, DNS records, WHOIS data, and NLP-based content analysis** to determine whether a link is safe or malicious.

This project was developed as part of a **Cyber Safety & Women's Security hackathon challenge**, aiming to help users identify phishing attacks commonly delivered through **messages, emails, and social media platforms**.

---

# 🚨 Problem Statement

Phishing attacks are one of the most common cyber threats today. Users frequently receive malicious links disguised as legitimate services through:

- SMS messages
- Social media platforms
- Email phishing campaigns
- Shortened URLs (bit.ly, tinyurl, etc.)

Many users cannot easily verify whether a link is safe before clicking it.

**LinkWarden AI solves this problem by providing instant phishing risk analysis.**

---

# ⚙️ Key Features

## 🔗 URL Phishing Detection
Analyzes links using machine learning to classify them as:
- Safe
- Suspicious
- Phishing

## 🧠 Multi-Layer Analysis
The model evaluates links using several security signals:

- URL lexical analysis
- Domain reputation
- DNS record validation
- WHOIS domain age analysis
- Suspicious TLD detection
- URL shortener expansion

## 🤖 AI/NLP Scam Detection
Uses **DistilBERT** to analyze messages containing links and detect scam intent.

Example:
"Your bank account has been suspended. Click here to verify."

---

# 🧰 Tech Stack

## Backend
- Python
- Flask
- Scikit-Learn
- Pandas
- tldextract
- python-whois
- dnspython

## AI / ML
- DistilBERT
- Transformers
- Logistic Regression
- Feature Engineering

## Frontend
- HTML
- CSS
- JavaScript

## Security Intelligence
- DNS Analysis
- WHOIS Lookup
- URL Lexical Features

---

# 📊 ML Features Used

The phishing detection model analyzes multiple indicators:

| Feature | Description |
|------|------|
| URL Length | Very long URLs are suspicious |
| Number of Dots | Multiple subdomains often indicate phishing |
| Suspicious TLD | `.xyz`, `.top`, `.click`, etc |
| Shortened URLs | bit.ly, tinyurl |
| Domain Age | Newly registered domains are risky |
| DNS Records | Missing records may indicate malicious domains |
| Query Parameters | Excessive parameters indicate obfuscation |

---
## 📸 Project Screenshots

### Safe Message Prediction
![Safe Prediction](https://raw.githubusercontent.com/jejo205713/linkwarden/main/working-images/safe-prediction.png)

### Suspicious Message Detection
![Suspicious Prediction](https://raw.githubusercontent.com/jejo205713/linkwarden/main/working-images/suspicious-prediction.png)

### Suspicious Message Example 2
![Suspicious Prediction 2](https://raw.githubusercontent.com/jejo205713/linkwarden/main/working-images/suspicious-prediction2.png)

### Malicious Message Detection
![Malicious Message](https://raw.githubusercontent.com/jejo205713/linkwarden/main/working-images/Message-legitimacy-malicious.png)

### Phishing Link Creation (Zphisher Example)
![Zphisher Attack Example](https://raw.githubusercontent.com/jejo205713/linkwarden/main/working-images/zphisher-phishing-link-creation.png)

---

# 🚀 Installation

## 1️⃣ Clone Repository

```bash
git clone https://github.com/yourusername/linkwarden-ai.git
cd linkwarden-ai
```
2️⃣ Create Virtual Environment
```
python3 -m venv venv
source venv/bin/activate
```
Linux / Mac
```
venv\Scripts\activate
```
Windows

3️⃣ Install Dependencies
```
pip install -r requirements.txt
```
▶️ Running the Application

Start the backend server:
```
python backend/app.py
```
Then open:
```
http://127.0.0.1:5000
```
---
🧪 Example Usage

Input URL:
```
http://paypal-security-update.xyz/login
```
Output:
```
Risk Score: 0.91
Classification: PHISHING
```

Telegram / WhatsApp bot for link scanning

Large-scale threat intelligence integration

Community phishing reporting system

Real-time domain reputation database

👨‍💻 Team

Team Dedcell

JEJO J

Cybersecurity Hackathon Project -Kreative Genesis (KGISL)

⚠️ Disclaimer

This tool is for educational and research purposes only.
