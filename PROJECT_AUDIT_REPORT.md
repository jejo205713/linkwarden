# LinkWarden — Project Audit Report

**Audit date:** 2026-05-08
**Scope:** full-stack stabilization, ML pipeline correction, India-localized scam detection, demo hardening.

---

## 1. Major fixes completed

### Frontend / API contract
- `frontend/static/script.js` is the live script (referenced from `index.html` at `/static/script.js`). The unreferenced `frontend/static/js/main.js` and `frontend/static/js/dashboard.js` were dead code expecting fields the backend never returned (`data.prediction`, `data.confidence`, `data.whois`, `data.threat_scores`). Both deleted.
- The live frontend-backend contract is now consistent: `status`, `confidence_score`, `expanded_url`, `domain_age_days`, `registrar`, `redirect_count`, `reasons`, `triggered_rules`, `risk_factors`, `model`.
- Radar chart was previously synthesized from the verdict + score (fake data). Now wired to `data.risk_factors` with four real axes: URL Structure, Domain Trust, Social Engineering, Technical Obfuscation.
- Geo trace was previously a hardcoded 3-city `url.length % 3` lookup. Replaced with a real DNS A → ip-api.com call returning IP, country, city, latitude, longitude, ASN, ISP, organization. SVG dot is now projected via equirectangular mapping from real lat/lon.
- `frontend/templates/bert.html` created (was missing — `/bert` previously 500'd).
- `frontend/static/report.js` created (was missing — incident form submission did nothing).

### Datasets
- `datasets/legitimate_dataset.csv` was empty header-only. Replaced via the deterministic generator at `model/generate_datasets.py` — currently 307 legitimate URLs covering Indian banks, govt portals (UIDAI/RBI/IRCTC/EPFO/income-tax), Tamil-Nadu state services, telcos, payments, e-commerce, news, education, and global tech.
- `datasets/phishing_urls.csv` was missing entirely. Now 554 phishing URLs covering: fake bank portals, UPI / payment scams, courier+customs scams, govt impersonation (UIDAI/IT-dept/EPFO/police), typosquatting, shorteners, IP-based phishing, subdomain spoofing, punycode/IDN homoglyphs, QR-payment lures, OTP-share lures, and Tamil-Nadu localized templates.
- Both files are reproducible (`python model/generate_datasets.py`) and seeded.

### ML pipeline
- **Removed:** the inverted Isolation-Forest setup — original code trained on phishing URLs only, so legitimate URLs became anomalies, which was backwards.
- **Added:** supervised `RandomForestClassifier` (300 estimators, `class_weight="balanced"`), wrapped in `CalibratedClassifierCV` (sigmoid, cv=3) for calibrated probabilities. Stratified 80/20 train/test split.
- **Kept as secondary:** an Isolation Forest trained on the legitimate distribution provides an anomaly score used to nudge borderline cases (30–65% confidence). It is no longer the primary signal.
- Model artefact (`model/phishing_model.pkl`) is now a versioned dict `{classifier, anomaly, feature_names, version}`. `model_loader.py` validates the schema and refuses stale artefacts.
- Training metrics (`model/training_metrics.json`) are written on every train: precision / recall / F1 / AUC / confusion matrix / feature importances.

### URL feature engineering hardening
The feature vector grew from 19 → 29 dimensions:

| Added feature | Detects |
|---|---|
| `punycode_flag` | `xn--` ACE-encoded hostnames |
| `homoglyph_flag` | Cyrillic look-alike chars in host |
| `unicode_in_host` | non-ASCII chars in host (rare for legit Indian sites) |
| `percent_encoded_count` | URL-encoded path/query obfuscation |
| `has_at_symbol` | `user@host` deception |
| `port_specified` | non-standard port (uncommon for legit consumer sites) |
| `upi_keyword_count` | UPI/payment lure vocabulary in URL |
| `subdomain_depth` | excessive subdomain depth |
| `longest_token_length` | random-looking 30+ char tokens |
| `host_length` | unusually long hostnames |

All feature extraction is now defensive — returns a stable vector even on garbage input (control bytes, malformed netloc, Unicode hostnames, type-confused inputs).

### Predictor / explainability
- `analyze_url()` now returns: `triggered_rules` (machine-readable rule IDs like `INSECURE_HTTP`, `TYPOSQUATTING_OF_PAYTM`, `HOMOGLYPH_HOST`), and `risk_factors` (four 0–100 axes for the radar chart).
- Typosquatting detector now tokenises hostnames on `-`/`_` and compares each token against a brand list that includes 14 Indian banks, 8 UPI/payment apps, and 8 govt brands (NPCI, RBI, UIDAI, IRCTC, EPFO, IndiaPost, etc.). Trusted-domain short-circuit prevents real brand hosts from self-flagging (e.g., `google.com` no longer trips against `googlepay`).
- Domain-age, redirect-count, and trusted-domain dampening preserved with corrected sign math.

### BERT / message scam engine
- DistilBERT now **lazy-loads** on first request. The Flask app starts even if `model/scam_distilbert_model/` is missing — heuristic-only mode is used as fallback.
- Response is now structured: `status`, `confidence_score`, `scam_probability`, `explanations`, `triggered_rules`, `matched_keywords`, `detected_categories`, `risk_factors` (4 axes: credential-phishing, money-lure, urgency-pressure, official-impersonation), and `model_available` flag.
- Keyword catalogue grew from 11 English words to ~80 entries spanning English, Hindi (Devanagari + transliterated), Tamil (Tamil script + transliterated), and India-specific scam vocabulary (UPI, KYC, OTP, refund, subsidy, pension, courier, customs).
- 22+ Tamil patterns added — both common roots (`கணக்கு`, `ஓடிபி`, `பணம்`, `பரிசு`, `கடவுச்சொல்`, `ஆதார்`) and full-phrase scam triggers (`உங்கள் கணக்கு தடுக்கப்பட்டது`, `கணக்கு முடக்கப்பட்டது`, `OTP பகிர வேண்டாம்`, `கைதுசெய்யப்படுவீர்கள்`, `காவல்துறை`, `நீதிமன்றம்`).

### Storage
- Reports were `print()`-only. Replaced with `backend/storage.py` using SQLite (`data/reports.sqlite`).
- New endpoint `GET /api/reports?limit=N` returns the most-recent reports, newest first, with parsed indicator arrays.
- `LINKWARDEN_REPORTS_FILE` env var still selects a JSONL fallback path (preserves the test contract).
- Persisted fields: `id`, `timestamp`, `name`, `email`, `phishing_url`, `incident_date`, `financial_loss`, `details`, `scan_result`, `risk_level`, `indicators` (JSON array).

### API hardening
- All four endpoints (`/api/analyze`, `/api/analyze-message`, `/api/geo`, `/api/report`) now:
  - Coerce arbitrary JSON values to strings without raising (numbers, lists, dicts, bools, nulls)
  - Bound input sizes (URL ≤ 2048 chars, message ≤ 8192 chars, details ≤ 5000)
  - Return structured `{"error": ...}` 400s on bad input
  - Catch all exceptions — never bubble a 500 to the client
- Custom 404/405 handlers return JSON for `/api/*` paths.
- `parsed.port` access is wrapped — Python 3.13 raises on malformed netlocs (`http://example.com:abc/`); the predictor now tolerates these.

---

## 2. ML metrics

| Metric | Value |
|---|---|
| Train rows | 688 |
| Test rows | 173 |
| Test precision | 1.00 |
| Test recall | 1.00 |
| Test F1 | 1.00 |
| Test ROC-AUC | 1.00 |
| Confusion matrix | `[[62, 0], [0, 111]]` |

**Top 10 features by importance**

| Feature | Importance |
|---|---|
| `has_https` | 0.245 |
| `suspicious_tld` | 0.171 |
| `num_hyphens` | 0.104 |
| `repeated_chars` | 0.082 |
| `domain_entropy` | 0.073 |
| `subdomain_depth` | 0.068 |
| `num_dots` | 0.056 |
| `num_subdomains` | 0.054 |
| `keyword_count` | 0.054 |
| `host_length` | 0.024 |

**Important caveat on the 100% scores:** the test set is drawn from the same synthetic distribution as training. The generator templates produce phishing URLs that are *too cleanly separable* from legitimate URLs (HTTP vs HTTPS, suspicious-TLD vs `.com`/`.in`, hyphenated brand-lures vs clean paths). The model has captured these signals correctly, but real-world phishing — particularly hosted on compromised legitimate domains, or phishing sites with valid Let's Encrypt certificates on `.com` — will score lower. **Production deployment must train against PhishTank / OpenPhish feeds and a domain-age-stratified legitimate sample**; the current dataset is sufficient for demo and feature-engineering validation only.

---

## 3. Stress test findings

The `tests/test_stress_battery.py` battery exercises 32 adversarial URL inputs and 8 message inputs across all four API endpoints. Categories:

| Category | Sample input | Outcome |
|---|---|---|
| Empty / whitespace | `""`, `" "`, `"\t\n"` | 400 error response |
| Missing scheme | `google.com` | scheme auto-prepended; 200 |
| Malformed | `http://`, `://no-scheme`, `http://[invalid` | 200 with degraded extraction |
| Bad port | `http://example.com:abc`, `http://1.2.3.4:99999` | 200 (was 500 — fixed) |
| Control bytes | `http://example.com/\x00null` | 200 |
| Long URLs | 1900 chars | 200; >2048 chars 400 |
| IPv6 | `http://[2001:db8::1]/` | 200 |
| Unicode hostnames | `http://தமிழ்.com/`, `http://हिन्दी.example/` | 200; flagged via `unicode_in_host` |
| Punycode/homoglyph | `http://xn--pypl-53dc3a.com/` | 200; flagged via `PUNYCODE_HOST` + `HOMOGLYPH_HOST` |
| `@`-trick | `http://google.com@evil.xyz/` | 200; flagged via `AT_SYMBOL_TRICK` |
| Type confusion | numeric/list/dict/bool/null URL value | 200 (was 500 — fixed) |
| Garbage JSON body | `"not json"` | 400 |

**Fixed during stress testing:**
1. `parsed.port` raised on `http://example.com:abc` — wrapped in try/except.
2. Type-confused payloads (`{"url": 12345}`, `{"url": ["a","b"]}`) raised `AttributeError` on `.strip()` — added `_str()` coercion in `app.py`.
3. `tldextract.extract(...)` raised on bracketed garbage in `http://[invalid` — wrapped in try/except in `predictor.py:detect_typosquatting()` and the trusted-domain check.
4. `urlparse(...)` raised `ValueError` on the bracketed-host case — `feature_extractor.py` wraps the call.

After fixes: **57/57 tests pass**, 0 unhandled 500s across the full battery.

---

## 4. Architecture changes

| Module | Before | After |
|---|---|---|
| `model/train_model.py` | IsolationForest, trained on phishing only | RandomForest + calibrated probs; IF kept as secondary on legit |
| `model/generate_datasets.py` | (none) | new — deterministic synthetic data with India-localized templates |
| `backend/feature_extractor.py` | 19 features, brittle on bad input | 29 features, defensive everywhere |
| `backend/predictor.py` | flat dict return, IsolationForest sign inverted, Western-only typosquat list | structured `triggered_rules` + `risk_factors`; supervised classifier; tokenised typosquat with Indian brands |
| `backend/bert_engine.py` | crashed at import if model dir missing; 11 EN keywords; flat return | lazy-loads model; ~80 keywords across English/Hindi/Tamil; structured response |
| `backend/storage.py` | (none) | new — SQLite store + `/api/reports` retrieval; JSONL fallback for tests |
| `backend/geo_lookup.py` | hardcoded 3-city sim | DNS A → ip-api.com (real IP/country/city/ASN/ISP) |
| `backend/app.py` | `print()` for reports, no input validation, missing `bert.html` route worked | hardened input validation, all errors return JSON, lazy BERT, sized payloads |
| `backend/model_loader.py` | unconditional load, returned raw model | thread-safe lazy load, schema-validated, returns dict artefact |
| `frontend/static/js/{main,dashboard}.js` | dead code, wrong contract | deleted |
| `frontend/static/script.js` | radar chart synthesised, simulated geo | radar reads `data.risk_factors`, geo reads `data.lat/lon` |
| `frontend/templates/bert.html` | missing | created — message-analysis UI with structured verdict box |

---

## 5. Remaining limitations

1. **Synthetic test set inflates metrics.** The 1.00 precision/recall is real for the synthetic distribution but should not be reported in user-facing materials without context. Real-world deployment requires PhishTank/OpenPhish feeds.
2. **Geo lookup is rate-limited.** ip-api.com free tier is ~45 req/min and HTTP-only. Under demo load this is fine; in production move to a paid tier or a self-hosted MaxMind DB.
3. **DistilBERT model is not in the repo.** `model/scam_distilbert_model/` is referenced but absent. The app now degrades gracefully (heuristic-only), but adding the trained weights is required to claim full BERT capability.
4. **No PII redaction in stored reports.** `data/reports.sqlite` will hold whatever the user submits. Add a redaction pass + retention policy before any real deployment.
5. **No rate limiting / abuse protection** on the API endpoints. A single client could exhaust the geo-lookup quota or hammer the model. Add Flask-Limiter or front the app with a reverse proxy that rate-limits.
6. **WHOIS lookups are blocking and slow** (`backend/whois_lookup.py` uses `python-whois` synchronously per request). Cache results, or move to an async worker, before serving real traffic.
7. **TLD extraction snapshot fix is a workaround.** `feature_extractor.py` writes a `~/.cache/linkwarden-tldextract` directory because some Debian builds of `tldextract` ship without their bundled snapshot. This works but adds a startup network fetch on first use.
8. **No frontend SVG escaping.** `reasonsList` uses `innerText` and is safe, but any future template that builds HTML from backend strings must use `textContent`/template literals carefully — phishing URLs themselves can contain script-like content.

---

## 6. Recommended future work

| Priority | Item |
|---|---|
| P0 | Replace synthetic phishing dataset with PhishTank + URLhaus feeds; retrain weekly. |
| P0 | Ship trained `scam_distilbert_model/` weights or document download path. |
| P1 | Add rate limiting (Flask-Limiter, 60 req/min/IP) + structured logging (JSON to stdout for ELK ingestion). |
| P1 | Implement the Telegram bot interface — forwarder pattern for SMS/UPI scam reports, replies with verdict + rule IDs. |
| P1 | PII redaction layer in `storage.py`: phone numbers, OTPs, account numbers, Aadhaar IDs. |
| P2 | Async WHOIS / DNS lookups with Redis-backed cache (1-hour TTL). |
| P2 | Replace ip-api.com with self-hosted MaxMind GeoLite2 + IPinfo's ASN DB. |
| P2 | Add an `/api/dashboard/stats` endpoint surfacing aggregate counts (last 24h scans, threat-status distribution) for a real ops dashboard instead of the current hardcoded "98.7% accuracy" sidebar. |
| P3 | Browser-extension wrapper around `/api/analyze` for click-through protection. |
| P3 | Unit tests for the BERT engine's category dispatcher (currently exercised only via integration tests). |

---

## 7. Verification

Final state:

```
$ python -m pytest tests/ -v
...
============================= 57 passed in 54.13s ==============================
```

End-to-end sample classifications (production model loaded):

| URL | Status | Score |
|---|---|---|
| `https://www.google.com` | SAFE | 0.6 |
| `https://www.sbi.co.in/web/personal-banking` | SAFE | low |
| `http://sbi-kyc-update.xyz/login` | PHISHING | 99.4 |
| `http://paaytm-rewards.gq` | PHISHING | 100.0 |
| `http://192.168.45.211/sbi/login` | PHISHING | 99.0 |
| `http://xn--pypl-53dc3a.com/login` | PHISHING | 99.0 |
| `http://bit.ly/abc123` | PHISHING | 99.3 |

All API endpoints return valid JSON for every input in the stress battery. The Flask app boots and serves all four routes (`/`, `/bert`, `/report`, `/api/*`) without requiring the optional DistilBERT artefact.
