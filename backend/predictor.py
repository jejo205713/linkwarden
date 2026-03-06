from feature_extractor import extract_url_features, get_feature_array
from url_expander import expand_url
from whois_lookup import get_domain_info
from model_loader import get_model
from utils import generate_explanations

from urllib.parse import urlparse
import tldextract
from Levenshtein import ratio


# ==========================================
# Known Brand List (for typosquatting check)
# ==========================================

TOP_BRANDS = [
    "facebook", "google", "paypal", "amazon", "instagram", "apple", 
    "microsoft", "netflix", "whatsapp", "twitter", "linkedin", 
    "github", "dropbox", "icloud", "bankofamerica"
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
    # 2️⃣ Extract Features (THE FIX)
    # Use original_url so the ML model sees the actual user input (typos, etc.)
    # ------------------------------------------
    features_dict = extract_url_features(original_url)
    features_array = get_feature_array(original_url)
    
    # 3️⃣ Domain Intelligence (Use final_url for accurate WHOIS/Age)
    domain_info = get_domain_info(final_url)


    # ------------------------------------------
    # 4️⃣ Isolation Forest Prediction
    # ------------------------------------------
    model = get_model()

    if model:
        # decision_function returns negative values for outliers (phishing)
        # We invert it or adjust to ensure higher scores = higher risk
        score = model.decision_function([features_array])[0]
        base_risk = 50 + (score * 100)
    else:
        base_risk = 0.0


    # Initial Boundaries
    risk_score = max(0, min(100, base_risk))


    # ==========================================
    # 👑 DOMAIN AGE OVERRIDE
    # ==========================================

    age = domain_info.get('age_days')

    if age is not None:
        if age > 1825:          # older than 5 years
            risk_score = risk_score * 0.1
        elif age > 365:         # older than 1 year
            risk_score = risk_score * 0.4
        elif age < 30:          # very new domain
            risk_score += 30
        elif age < 3:           # extremely new
            risk_score = 99


    # ==========================================
    # 🛑 Typosquatting Detection
    # ==========================================
    # We check against the original_url to catch the typo!
    typo_detected, brand, similarity = detect_typosquatting(original_url)

    if typo_detected:
        risk_score += 40
        features_dict["typosquatting"] = True
        features_dict["impersonated_brand"] = brand
    else:
        features_dict["typosquatting"] = False


    # ==========================================
    # Final Risk Score Bound
    # ==========================================
    confidence_score = round(max(0, min(100, risk_score)), 2)


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
    # Explanations
    # ==========================================
    reasons = generate_explanations(
        features_dict,
        domain_info,
        redirect_count,
        is_phishing
    )

    if typo_detected:
        reasons.append(f"Domain resembles brand '{brand}' (possible typosquatting)")


    # ==========================================
    # Final Response
    # ==========================================
    return {
        "original_url": original_url,
        "expanded_url": final_url,
        "status": status,
        "confidence_score": confidence_score,
        "domain_age_days": age if age else "Unknown",
        "registrar": domain_info.get('registrar', 'Unknown'),
        "redirect_count": redirect_count,
        "reasons": reasons
    }