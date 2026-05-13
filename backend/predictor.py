"""LinkWarden URL analyzer.

Returns a structured response that the frontend renders directly:

    {
        "status": "SAFE" | "SUSPICIOUS" | "PHISHING",
        "confidence_score": 0..100,
        "expanded_url": str,
        "redirect_count": int,
        "domain_age_days": int | "Unknown",
        "registrar": str,
        "reasons": [str, ...],
        "triggered_rules": [str, ...],
        "risk_factors": {
            "url_structure": 0..100,
            "domain_trust":   0..100,
            "social_engineering": 0..100,
            "technical_obfuscation": 0..100,
        },
        "model": {
            "phishing_probability": 0..1,
            "anomaly_score": float,
            "version": int,
            "available": bool,
        },
    }
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

import tldextract
from Levenshtein import ratio

from feature_extractor import extract_url_features, get_feature_array
from url_expander import expand_url
from whois_lookup import get_domain_info
from model_loader import get_model_artefact
from utils import generate_explanations


# ---------------------------------------------------------------------------
# Brand lists
# ---------------------------------------------------------------------------

TOP_BRANDS = [
    # Global
    "facebook", "google", "paypal", "amazon", "instagram", "apple",
    "microsoft", "netflix", "whatsapp", "twitter", "linkedin",
    "github", "dropbox", "icloud", "bankofamerica",
    # Indian banks
    "sbi", "hdfc", "icici", "axis", "kotak", "canara", "pnb", "unionbank",
    "indianbank", "bobibank", "yesbank", "idfc", "federalbank", "indusind", "rblbank",
    # UPI / payments
    "paytm", "phonepe", "gpay", "googlepay", "bhim", "mobikwik", "freecharge", "cred",
    # Govt / quasi-govt
    "npci", "rbi", "uidai", "aadhaar", "incometax", "irctc", "epfo", "indiapost",
]

TRUSTED_DOMAINS = [
    "google", "youtube", "facebook", "whatsapp", "instagram",
    "amazon", "apple", "microsoft", "openai", "chatgpt",
    "netflix", "linkedin", "github", "cloudflare", "twitter",
    # Indian legitimate brands
    "sbi", "hdfcbank", "icicibank", "axisbank", "kotak",
    "paytm", "phonepe", "npci", "rbi", "uidai", "irctc", "indiapost",
    "flipkart", "zomato", "swiggy", "myntra", "ajio", "makemytrip",
    "iitm", "iisc", "nptel", "swayam", "tn",
]


# ---------------------------------------------------------------------------
# Typosquatting (token-aware, trusted-domain-aware)
# ---------------------------------------------------------------------------

def detect_typosquatting(url: str):
    try:
        ext = tldextract.extract(url)
    except Exception:  # noqa: BLE001
        return False, None, 0
    domain = (ext.domain or "").lower()

    if not domain or domain in TRUSTED_DOMAINS:
        return False, None, 0

    tokens = {tok for tok in re.split(r"[-_]", domain) if tok}
    tokens.add(domain)

    for brand in TOP_BRANDS:
        if domain == brand or brand in tokens:
            continue
        for token in tokens:
            len_diff = abs(len(token) - len(brand))
            if len_diff > 3:
                continue
            if len(brand) >= 3 and brand in token:
                return True, brand, 1.0
            similarity = ratio(token, brand)
            if similarity > 0.80:
                return True, brand, similarity

    return False, None, 0


# ---------------------------------------------------------------------------
# Risk-vector aggregation (radar chart axes)
# ---------------------------------------------------------------------------

def _risk_vectors(features: dict, redirect_count: int, typo_brand: str | None) -> dict:
    """Aggregate raw features into the four radar-chart axes.

    Each axis is normalized 0..100. Values are clipped, not validated — this
    is a presentation summary, not a model output.
    """
    # Cap helpers
    def cap(v, top=100): return max(0, min(top, v))

    # 1. URL structure: length, dots, subdomains, hyphens, digits, IP-host.
    structure = (
        min(features["url_length"] / 1.5, 40)
        + features["num_hyphens"] * 6
        + features["num_subdomains"] * 8
        + (features["digit_ratio"] * 60)
        + (30 if features["has_ip"] else 0)
    )

    # 2. Domain trust: HTTPS, suspicious TLD, free hosting, repeated chars,
    # punycode/homoglyph, trusted-domain bonus removed from this axis.
    trust = (
        (35 if not features["has_https"] else 0)
        + (40 if features["suspicious_tld"] else 0)
        + (30 if features["free_hosting_flag"] else 0)
        + (25 if features["repeated_chars"] else 0)
        + (40 if features["punycode_flag"] else 0)
        + (40 if features["homoglyph_flag"] else 0)
    )

    # 3. Social engineering: scam keywords, UPI lure keywords, typosquat hit.
    social = (
        features["keyword_count"] * 12
        + features["upi_keyword_count"] * 14
        + (45 if typo_brand else 0)
    )

    # 4. Technical obfuscation: shorteners, redirects, percent-encoding, @ tricks,
    # high entropy, long random-looking tokens, non-default ports, unicode in host.
    obfuscation = (
        (40 if features["shortener_flag"] else 0)
        + (redirect_count * 12)
        + (features["percent_encoded_count"] * 5)
        + (35 if features["has_at_symbol"] else 0)
        + max(0, (features["url_entropy"] - 4.0) * 30)
        + (20 if features["unicode_in_host"] else 0)
        + (15 if features["port_specified"] else 0)
        + max(0, (features["longest_token_length"] - 25) * 2)
    )

    return {
        "url_structure": round(cap(structure), 1),
        "domain_trust": round(cap(trust), 1),
        "social_engineering": round(cap(social), 1),
        "technical_obfuscation": round(cap(obfuscation), 1),
    }


def _triggered_rules(features: dict, age_days, redirect_count: int, typo_brand: str | None) -> list[str]:
    rules = []
    if features["has_ip"]:
        rules.append("URL_USES_RAW_IP")
    if features["has_https"] == 0:
        rules.append("INSECURE_HTTP")
    if features["suspicious_tld"]:
        rules.append("SUSPICIOUS_TLD")
    if features["shortener_flag"]:
        rules.append("URL_SHORTENER_HOST")
    if features["free_hosting_flag"]:
        rules.append("FREE_HOSTING_PLATFORM")
    if features["punycode_flag"]:
        rules.append("PUNYCODE_HOST")
    if features["homoglyph_flag"]:
        rules.append("HOMOGLYPH_HOST")
    if features["unicode_in_host"]:
        rules.append("UNICODE_IN_HOST")
    if features["has_at_symbol"]:
        rules.append("AT_SYMBOL_TRICK")
    if features["repeated_chars"]:
        rules.append("REPEATED_CHARS_IN_HOST")
    if features["keyword_count"] >= 1:
        rules.append("PHISHING_KEYWORDS_IN_URL")
    if features["upi_keyword_count"] >= 1:
        rules.append("UPI_PAYMENT_LURE_KEYWORDS")
    if features["num_subdomains"] >= 3:
        rules.append("EXCESSIVE_SUBDOMAIN_DEPTH")
    if redirect_count >= 2:
        rules.append("MULTIPLE_REDIRECTS")
    if features["percent_encoded_count"] >= 3:
        rules.append("HIGH_PERCENT_ENCODING")
    if isinstance(age_days, int) and age_days < 30:
        rules.append("VERY_NEW_DOMAIN")
    if typo_brand:
        rules.append(f"TYPOSQUATTING_OF_{typo_brand.upper()}")
    return rules


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

def analyze_url(original_url: str) -> dict:
    if not isinstance(original_url, str):
        original_url = str(original_url)
    original_url = original_url.strip()

    # 1. Expand
    try:
        expanded_res = expand_url(original_url)
        final_url, redirect_count = expanded_res[0], expanded_res[1]
    except Exception:
        final_url, redirect_count = original_url, 0

    # 2. Features
    features_dict = extract_url_features(original_url)
    features_array = get_feature_array(original_url)

    # 3. WHOIS / domain age
    try:
        domain_info = get_domain_info(final_url)
    except Exception:
        domain_info = {"age_days": None, "registrar": "Unknown", "dns_records": 0}

    # 4. Model inference (supervised classifier + secondary anomaly score)
    artefact = get_model_artefact()
    if artefact is not None:
        clf = artefact["classifier"]
        iforest = artefact.get("anomaly")
        try:
            phish_proba = float(clf.predict_proba([features_array])[0][1])
        except Exception:
            phish_proba = 0.5
        try:
            anomaly_score = float(iforest.decision_function([features_array])[0]) if iforest else 0.0
        except Exception:
            anomaly_score = 0.0
        model_available = True
        version = artefact.get("version", 1)
    else:
        phish_proba = 0.5
        anomaly_score = 0.0
        model_available = False
        version = 0

    base_risk = phish_proba * 100.0

    # 5. Domain age adjustment
    age = domain_info.get("age_days")
    registrar = domain_info.get("registrar", "")
    if registrar and "RESERVED" in str(registrar).upper():
        age = None

    if isinstance(age, int):
        if age < 3:
            base_risk = max(base_risk, 90)
        elif age < 30:
            base_risk += 15
        elif age > 1825:
            base_risk *= 0.85
        elif age > 365:
            base_risk *= 0.92

    # 6. Typosquatting bump
    typo_detected, brand, similarity = detect_typosquatting(original_url)
    if typo_detected:
        base_risk += 30
        features_dict["typosquatting"] = True
        features_dict["impersonated_brand"] = brand
    else:
        features_dict["typosquatting"] = False

    # 7. Trusted-domain dampening (only when model isn't already very confident)
    try:
        ext = tldextract.extract(original_url)
        domain = (ext.domain or "").lower()
    except Exception:  # noqa: BLE001
        domain = ""
    if domain in TRUSTED_DOMAINS and base_risk < 70:
        base_risk *= 0.5

    # 8. Anomaly nudge for borderline cases
    if model_available and 30 < base_risk < 65 and anomaly_score < -0.05:
        base_risk += 10

    confidence_score = round(max(0.0, min(100.0, base_risk)), 2)

    # 9. Verdict
    if confidence_score >= 65:
        status, is_phishing = "PHISHING", True
    elif confidence_score >= 40:
        status, is_phishing = "SUSPICIOUS", True
    else:
        status, is_phishing = "SAFE", False

    # 10. Build response
    reasons = generate_explanations(features_dict, domain_info, redirect_count, is_phishing)
    if typo_detected:
        reasons.append(f"Domain resembles brand '{brand}' (possible typosquatting)")

    triggered = _triggered_rules(features_dict, age, redirect_count, brand if typo_detected else None)
    risk_factors = _risk_vectors(features_dict, redirect_count, brand if typo_detected else None)

    return {
        "original_url": original_url,
        "expanded_url": final_url,
        "status": status,
        "confidence_score": confidence_score,
        "domain_age_days": age if isinstance(age, int) else "Unknown",
        "registrar": registrar or "Unknown",
        "redirect_count": int(redirect_count),
        "reasons": reasons,
        "triggered_rules": triggered,
        "risk_factors": risk_factors,
        "model": {
            "phishing_probability": round(phish_proba, 4),
            "anomaly_score": round(anomaly_score, 4),
            "available": model_available,
            "version": version,
        },
    }
