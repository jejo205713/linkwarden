from feature_extractor import extract_url_features, get_feature_array
from url_expander import expand_url
from whois_lookup import get_domain_info
from model_loader import get_model
from utils import generate_explanations

import tldextract
from Levenshtein import ratio


# ==========================================
# Known Brand List (Typosquatting Detection)
# ==========================================

TOP_BRANDS = [
    "facebook","google","paypal","amazon","instagram","apple",
    "microsoft","netflix","whatsapp","twitter","linkedin",
    "github","dropbox","icloud","bankofamerica"
]


# ==========================================
# Trusted Domains (Prevent False Positives)
# ==========================================

TRUSTED_DOMAINS = [
    "google","youtube","facebook","whatsapp","instagram",
    "amazon","apple","microsoft","openai","chatgpt",
    "netflix","linkedin","github","cloudflare"
]


# ==========================================
# Typosquatting Detection
# ==========================================

def detect_typosquatting(url):

    ext = tldextract.extract(url)
    domain = ext.domain.lower()

    for brand in TOP_BRANDS:

        similarity = ratio(domain, brand)

        if similarity > 0.80 and domain != brand:
            return True, brand, similarity

    return False, None, 0


# ==========================================
# Main Analyzer
# ==========================================

def analyze_url(original_url):

    # ------------------------------------------
    # 1️⃣ Expand URL safely
    # ------------------------------------------

    try:
        expanded_res = expand_url(original_url)
        final_url = expanded_res[0]
        redirect_count = expanded_res[1]

    except Exception:

        final_url = original_url
        redirect_count = 0


    # ------------------------------------------
    # 2️⃣ Extract Features
    # ------------------------------------------

    features_dict = extract_url_features(original_url)
    features_array = get_feature_array(original_url)


    # ------------------------------------------
    # 3️⃣ Domain Intelligence
    # ------------------------------------------

    domain_info = get_domain_info(final_url)


    # ------------------------------------------
    # 4️⃣ Isolation Forest Prediction
    # ------------------------------------------

    model = get_model()

    if model:

        score = model.decision_function([features_array])[0]

        base_risk = 50 + (score * 100)

    else:

        base_risk = 0.0


    risk_score = max(0, min(100, base_risk))


    # ==========================================
    # DOMAIN AGE ADJUSTMENT
    # ==========================================

    age = domain_info.get("age_days")
    registrar = domain_info.get("registrar","")

    # Ignore reserved domains (.example)
    if registrar and "RESERVED" in registrar.upper():
        age = None


    if age is not None:

        if age < 3:
            risk_score = max(risk_score, 90)

        elif age < 30:
            risk_score += 25

        elif age > 1825:
            risk_score *= 0.7

        elif age > 365:
            risk_score *= 0.85


    # ==========================================
    # HTTP Penalty (very small)
    # ==========================================

    if original_url.startswith("http://"):
        risk_score += 5


    # ==========================================
    # Typosquatting Detection
    # ==========================================

    typo_detected, brand, similarity = detect_typosquatting(original_url)

    if typo_detected:

        risk_score += 40

        features_dict["typosquatting"] = True
        features_dict["impersonated_brand"] = brand

    else:

        features_dict["typosquatting"] = False


    # ==========================================
    # Trusted Domain Adjustment
    # ==========================================

    ext = tldextract.extract(original_url)
    domain = ext.domain.lower()

    if domain in TRUSTED_DOMAINS:

        # Only reduce mild false positives
        if risk_score < 70:
            risk_score *= 0.5


    # ==========================================
    # Final Risk Score
    # ==========================================

    confidence_score = round(max(0, min(100, risk_score)),2)


    # ==========================================
    # Verdict Logic
    # ==========================================

    if confidence_score >= 65:

        status = "PHISHING"
        is_phishing = True

    elif confidence_score >= 40:

        status = "SUSPICIOUS"
        is_phishing = True

    else:

        status = "SAFE"
        is_phishing = False


    # ==========================================
    # Generate Explanations
    # ==========================================

    reasons = generate_explanations(
        features_dict,
        domain_info,
        redirect_count,
        is_phishing
    )


    if typo_detected:

        reasons.append(
            f"Domain resembles brand '{brand}' (possible typosquatting)"
        )


    # ==========================================
    # Final API Response
    # ==========================================

    return {

        "original_url": original_url,
        "expanded_url": final_url,

        "status": status,
        "confidence_score": confidence_score,

        "domain_age_days": age if age else "Unknown",
        "registrar": domain_info.get("registrar","Unknown"),

        "redirect_count": redirect_count,

        "reasons": reasons
    }