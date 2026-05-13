# LinkWarden AI

**Intelligent Phishing and Scam Detection Platform — India-localized**

LinkWarden AI is a machine-learning–driven cybersecurity platform that detects phishing URLs and scam SMS / WhatsApp messages in real time. It combines a calibrated supervised classifier with a structured rules engine to produce explainable, human-readable verdicts — tuned specifically for the Indian threat landscape: UPI and payment scams, KYC and OTP lures, courier and customs fraud, fake bank portals, and Tamil / Hindi message scams.

Built for the **WitchHunt Cybersecurity Hackathon** by **Team Dedcell**.

---

## Problem Statement

India sees millions of phishing attempts daily, delivered as:

- UPI and banking SMS ("your KYC will be blocked — act now")
- Courier and customs scams ("pay Rs. 99 to release your package")
- Government impersonation (RBI, UIDAI, Income Tax, EPFO, IRCTC)
- Typosquatted brand domains (`paaytm-rewards.gq`, `phonpepe-cashback.tk`)
- Shortened URLs that hide the real destination
- Tamil and Hindi messages that bypass English-only filters

In 2025 alone, India reported over **1.1 million cybercrime cases**. Existing tools either block silently or only work in English. LinkWarden gives users an **instant, explainable verdict** — so they understand *why* a link is dangerous, not just *that* it is.

---

## What We Built

During this hackathon, Team Dedcell:

- Built the full URL phishing detection pipeline — a 29-feature ML model (calibrated RandomForest plus IsolationForest) with a rules engine
- Built multilingual scam message analysis covering English, Hindi (Devanagari and transliterated) and Tamil (script and transliterated) with 80+ keywords and 22+ Tamil scam patterns
- Built SQLite-backed incident reporting with structured storage and retrieval
- Fixed the Geo Intelligence endpoint — it was returning `Unknown` for every domain. Root cause: the DNS pre-resolution step failed for offline or non-existent phishing domains, blocking the ip-api.com call entirely. Fix: pass the hostname directly to ip-api.com (which accepts hostnames natively), removing the broken DNS dependency.
- Fixed a merge conflict in `app.py` that caused a `SyntaxError` on startup
- Validated that all 57 tests pass — including a 32-input adversarial stress battery covering malformed URLs, null bytes, Unicode, IPv6, oversized payloads and wrong HTTP methods

---

## Features

### URL Analysis — `POST /api/analyze`

Returns a structured verdict:

| Field | Meaning |
|---|---|
| `status` | `SAFE` / `SUSPICIOUS` / `PHISHING` |
| `confidence_score` | 0 to 100 |
| `reasons` | Human-readable explanations |
| `triggered_rules` | Machine-readable rule IDs (`INSECURE_HTTP`, `TYPOSQUATTING_OF_PAYTM`, `HOMOGLYPH_HOST`, ...) |
| `risk_factors` | Four 0–100 axes: URL Structure, Domain Trust, Social Engineering, Technical Obfuscation |
| `model.phishing_probability` | Calibrated probability from the supervised classifier |
| `model.anomaly_score` | Secondary IsolationForest signal |
| `domain_age_days`, `registrar` | WHOIS enrichment |
| `expanded_url`, `redirect_count` | Shortener resolution |

### Message Scam Analysis — `POST /api/analyze-message`

DistilBERT classification combined with a heuristic catalogue of 80+ keywords across English, Hindi and Tamil. DistilBERT lazy-loads — if the model weights are absent, the app runs in heuristic-only mode and exposes `model_available: false` so the front-end can display the correct engine status.

Returns: `status`, `confidence_score`, `scam_probability`, `explanations`, `triggered_rules`, `matched_keywords`, `detected_categories`, `model_available`, and a 4-axis `risk_factors` breakdown (credential phishing, money lure, urgency pressure, official impersonation).

### Geo Intelligence — `POST /api/geo`

Hostname to IP, country, city, ASN, ISP and organization via ip-api.com. Works for live domains and gracefully handles non-existent phishing domains. The dashboard map dot uses real latitude / longitude coordinates.

### Incident Reports — `POST /api/report`, `GET /api/reports`

SQLite-backed (`data/reports.sqlite`). Stores timestamp, victim contact, phishing URL, financial loss and indicators. `GET /api/reports?limit=N` returns the most recent N reports, newest first.

---

## Tech Stack

| Layer | Technologies |
|---|---|
| Backend | Python 3, Flask, Flask-CORS |
| ML | Calibrated RandomForest plus IsolationForest, DistilBERT (lazy-loaded) |
| Feature Engineering | scikit-learn, pandas, NumPy, tldextract, python-Levenshtein |
| Domain Intelligence | python-whois, dnspython, ip-api.com |
| Frontend | Vanilla HTML / CSS / JS, Chart.js (radar chart) |
| Storage | SQLite (default), JSONL fallback |
| Tests | pytest — 57 tests, 32-input adversarial stress battery |

---

## ML Pipeline

The URL model is a **calibrated supervised RandomForest** trained on a labelled union of legitimate and phishing URLs.

| Metric | Value |
|---|---|
| Precision | 1.00 |
| Recall | 1.00 |
| F1 | 1.00 |
| ROC-AUC | 1.00 |
| Train rows | 688 |
| Test rows | 173 |

> **Note:** The 1.00 scores reflect the synthetic dataset's clean separability. Production deployment benefits from retraining against PhishTank or OpenPhish feeds. See `PROJECT_AUDIT_REPORT.md`.

**Top features:** `has_https`, `suspicious_tld`, `num_hyphens`, `repeated_chars`, `domain_entropy`, `subdomain_depth`, `num_dots`, `num_subdomains`, `keyword_count`.

The 29-dimensional feature vector covers URL structure, lexical analysis, suspicious TLDs, free hosting detection, shortener detection, punycode / IDN homoglyph detection, percent-encoding abuse, `@`-symbol tricks, IP-based hosts, UPI / payment lure keywords, subdomain depth and longest-token length.

---

## Quick Start

```bash
git clone https://github.com/jejo205713/linkwarden.git
cd linkwarden
./start.sh
```

`start.sh` will:

1. Verify `python3` is installed
2. Create `./.venv` (or use system Python with `LINKWARDEN_NO_VENV=1`)
3. Install all dependencies and patch missing packages
4. Generate synthetic datasets if missing
5. Train the URL model if `phishing_model.pkl` is absent (or set `LINKWARDEN_RETRAIN=1`)
6. Start Flask on `http://0.0.0.0:5000`

Open `http://127.0.0.1:5000` in your browser.

### Windows (CMD)

```cmd
cd linkwarden
pip install -r requirements.txt
pip install python-Levenshtein
python model\generate_datasets.py
python model\train_model.py
python backend\app.py
```

### Manual Install (Linux / macOS)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install python-Levenshtein
python model/generate_datasets.py
python model/train_model.py
python backend/app.py
```

### Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `LINKWARDEN_HOST` | `0.0.0.0` | Bind host |
| `LINKWARDEN_PORT` | `5000` | Bind port |
| `LINKWARDEN_RETRAIN` | `0` | Set to `1` to force URL model retraining |
| `LINKWARDEN_NO_VENV` | `0` | Set to `1` to use system Python |
| `LINKWARDEN_REPORTS_DB` | `data/reports.sqlite` | SQLite path |
| `LINKWARDEN_REPORTS_FILE` | unset | Overrides SQLite with JSONL (used by tests) |

---

## DistilBERT Installation (Optional but Recommended)

DistilBERT powers the `/bert` message scam analyzer. The app **starts and serves traffic without the model** — it falls back to heuristic-only mode and reports `model_available: false`. To enable the full neural classifier, install the model weights into `model/scam_distilbert_model/`. Follow the steps below.

### Step 1 — Install the Transformers stack

The base `requirements.txt` does **not** include `transformers` or `torch`. Install them into the same environment that runs `backend/app.py`.

```bash
# If you used start.sh, activate the venv it created:
source .venv/bin/activate

# CPU build (recommended for most laptops and the hackathon demo):
pip install transformers==4.41.2 torch==2.3.1 --extra-index-url https://download.pytorch.org/whl/cpu

# Or, if you have a CUDA-capable GPU:
pip install transformers==4.41.2 torch==2.3.1
```

Verify both imports succeed:

```bash
python -c "import torch, transformers; print('torch', torch.__version__, '/ transformers', transformers.__version__)"
```

### Step 2 — Create the model directory

The backend looks for the model at exactly this path (see `backend/bert_engine.py`, constant `MODEL_PATH`):

```
model/scam_distilbert_model/
```

```bash
mkdir -p model/scam_distilbert_model
```

### Step 3 — Choose a model source

You have three options, listed in order of preference for this project.

#### Option A — Use a project-trained checkpoint (best results, requires training data)

If you have a fine-tuned scam classifier from `model/train_distilbert.py` or an equivalent script, copy its output directory contents into `model/scam_distilbert_model/`. The expected files are:

```
model/scam_distilbert_model/
├── config.json
├── model.safetensors        (or pytorch_model.bin)
├── tokenizer_config.json
├── tokenizer.json
├── vocab.txt
└── special_tokens_map.json
```

#### Option B — Download a pre-trained DistilBERT from Hugging Face (fastest)

This pulls the base `distilbert-base-uncased` weights and saves them in the project-required layout. The base model is **not** scam-tuned out of the box; it will produce moderate-quality verdicts that the heuristic catalogue refines. Run from the project root:

```bash
python - <<'PY'
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
TARGET = "model/scam_distilbert_model"
tok = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
mdl = DistilBertForSequenceClassification.from_pretrained(
    "distilbert-base-uncased", num_labels=2
)
tok.save_pretrained(TARGET)
mdl.save_pretrained(TARGET)
print("Saved DistilBERT weights to", TARGET)
PY
```

This requires outbound HTTPS access to `huggingface.co` on first run. After it completes, the files listed in Option A will be present.

#### Option C — Use a community fine-tuned scam / phishing model

Replace `MODEL_NAME` below with any DistilBERT-architecture binary classifier from Hugging Face (for example `mrm8488/bert-tiny-finetuned-sms-spam-detection` if the architecture matches; verify it is DistilBERT-based, otherwise use Option B). Run from the project root:

```bash
python - <<'PY'
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
MODEL_NAME = "distilbert-base-uncased"   # replace with chosen model
TARGET = "model/scam_distilbert_model"
tok = DistilBertTokenizerFast.from_pretrained(MODEL_NAME)
mdl = DistilBertForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)
tok.save_pretrained(TARGET)
mdl.save_pretrained(TARGET)
PY
```

### Step 4 — Verify the install

Start the server (`./start.sh` or `python backend/app.py`) and watch the console. On the first request to `/api/analyze-message` you should see:

```
[bert_engine] DistilBERT loaded.
```

If you instead see `[bert_engine] model dir not found ...` or `[bert_engine] failed to load DistilBERT ...`, the app continues running in heuristic mode — re-check the path and that `config.json` plus weights live directly inside `model/scam_distilbert_model/` (not nested in another folder).

### Step 5 — Confirm from the UI

Open `http://127.0.0.1:5000/bert`, paste any message and submit. The Detection Summary card shows:

- `Model Status: DistilBERT loaded` when the weights are active
- `Model Status: Heuristic-only mode` when the fallback is in effect

The sidebar engine indicator and bar update to match.

---

## Tests

```bash
python -m pytest tests/ -v
```

**57 tests — all passing.** Coverage includes:

- Predictor contract (status thresholds, response shape)
- Indian-brand typosquatting detection (SBI, Paytm, PhonePe, HDFC — plus real SBI correctly not flagged)
- Report persistence and retrieval ordering
- 32+ adversarial URL inputs (malformed, oversize, null bytes, type-confused, IDN, IPv6, control characters) — guaranteed never to return HTTP 500

---

## API Routes

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Threat dashboard (URL scanner) |
| `/bert` | GET | Message scam analysis |
| `/report` | GET | Incident report form |
| `/api/analyze` | POST | URL phishing analysis |
| `/api/analyze-message` | POST | Message scam analysis |
| `/api/geo` | POST | Hostname to IP / country / ASN / ISP lookup |
| `/api/report` | POST | Submit incident report |
| `/api/reports?limit=N` | GET | List recent reports (newest first) |

---

## Sample Classifications

### URLs

| URL | Verdict | Score |
|---|---|---|
| `https://www.google.com` | SAFE | 0.58 |
| `https://www.sbi.co.in/web/personal-banking` | SAFE | 0.53 |
| `https://www.amazon.in/ap/signin` | SAFE | 0.55 |
| `http://sbi-kyc-update.xyz/login` | PHISHING | 99.4 |
| `http://paaytm-rewards.gq` | PHISHING | 100.0 |
| `http://phonpepe-cashback.tk` | PHISHING | 99.4 |
| `http://192.168.45.211/sbi/login` | PHISHING | 99.0 |
| `http://xn--pypl-53dc3a.com/login` | PHISHING | 99.0 |
| `http://bit.ly/abc123` | PHISHING | 99.3 |

### Messages

```
URGENT: Your SBI account will be blocked. Share your OTP immediately.
  status=PHISHING, categories=[credential_phishing, urgency_pressure, official_impersonation]

Aapka SBI khata band ho gaya hai. OTP de turant.
  status=SUSPICIOUS, matched=['otp', 'khata', 'band ho', 'turant']

[Tamil] Your SBI account is locked. Share OTP: http://bit.ly/abc
  status=SUSPICIOUS, matched=['kanaku', 'OTP'], category=credential_phishing

Hi, your food order will arrive in 30 minutes.
  status=SAFE, score=0.0
```

---

## Project Layout

```
linkwarden/
  backend/
    app.py                  Flask routes and hardened input validation
    predictor.py            URL analyzer (structured response)
    feature_extractor.py    29-feature URL vector
    bert_engine.py          Message scam analyzer (lazy DistilBERT)
    storage.py              SQLite + JSONL report store
    geo_lookup.py           ip-api.com hostname to IP / country / city / ASN / ISP
    url_expander.py         Shortener resolution
    whois_lookup.py         WHOIS / domain age
    dns_lookup.py           DNS records
    model_loader.py         Lazy, thread-safe model artefact loader
    utils.py                Human-readable explanation builder
  frontend/
    static/                 script.js, report.js, style.css
    templates/              index.html, report.html, bert.html
  datasets/
    legitimate_dataset.csv  307 rows (regenerable)
    phishing_urls.csv       554 rows (regenerable)
  model/
    generate_datasets.py    Deterministic dataset generator
    train_model.py          Supervised RF training pipeline
    phishing_model.pkl      Versioned artefact (classifier, anomaly, feature_names, version)
    training_metrics.json   Precision / recall / F1 / AUC plus feature importances
    scam_distilbert_model/  DistilBERT weights (created by user — see install steps)
  tests/                    57 tests, including adversarial stress battery
  data/                     Runtime SQLite (gitignored)
  start.sh                  One-command startup
  requirements.txt
  PROJECT_AUDIT_REPORT.md   Full technical audit
```

---

## Roadmap

- Replace synthetic dataset with PhishTank / OpenPhish feeds (P0)
- Ship trained DistilBERT weights or document download path (P0)
- Rate limiting (Flask-Limiter, 60 req/min/IP) and structured JSON logging (P1)
- Telegram bot — forward suspicious SMS, get verdict and rule IDs (P1)
- PII redaction for stored reports (phone, OTP, account, Aadhaar) (P1)
- Async WHOIS / DNS with Redis cache (P2)
- MaxMind GeoLite2 and IPinfo ASN DB (replace ip-api free tier) (P2)
- Browser extension wrapping `/api/analyze` (P3)

See `PROJECT_AUDIT_REPORT.md` for the full technical audit.

---

## Team

**Team Dedcell** — WitchHunt Cybersecurity Hackathon

| Name | Role |
|---|---|
| Jejo J | Backend, ML pipeline and system architecture |
| Shreya V | Security research and frontend development |
| Sridevi S | Frontend development and UI |
| Pavithra M | Project development and presentation |

---

## Disclaimer

This tool is for **educational and research purposes only**. The synthetic training data is not a substitute for production threat-intelligence feeds. Verdicts should be treated as advisory, not authoritative.
