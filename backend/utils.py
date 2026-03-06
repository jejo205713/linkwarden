def generate_explanations(features, domain_info, redirect_count, is_phishing):
    """Generate human readable reasons for the UI"""

    reasons = []

    # Redirect detection
    if redirect_count > 1:
        reasons.append(f"⚠️ Multiple redirects detected ({redirect_count} redirects).")

    # Keyword detection
    if features.get("keyword_count", 0) > 0:
        reasons.append("⚠️ URL contains phishing-related keywords (login, verify, secure, etc).")

    # IP address usage
    if features.get("has_ip") == 1:
        reasons.append("⚠️ URL uses an IP address instead of a normal domain.")

    # Subdomain abuse
    if features.get("num_subdomains", 0) >= 3:
        reasons.append(f"⚠️ High number of subdomains detected ({features['num_subdomains']}).")

    # Suspicious TLD
    if features.get("suspicious_tld") == 1:
        reasons.append("⚠️ Suspicious top-level domain detected.")

    # Free hosting abuse
    if features.get("free_hosting_flag") == 1:
        reasons.append("⚠️ Domain hosted on free hosting platform often used for phishing.")

    # Entropy detection
    if features.get("url_entropy", 0) > 4.2:
        reasons.append("⚠️ URL appears highly obfuscated (high entropy).")

    # Digit heavy URLs
    if features.get("digit_ratio", 0) > 0.3:
        reasons.append("⚠️ URL contains unusually high number of digits.")

    # Domain age
    age = domain_info.get("age_days")

    if age is not None:

        if age < 7:
            reasons.append(f"⚠️ Domain registered extremely recently ({age} days old).")

        elif age < 30:
            reasons.append(f"⚠️ Newly registered domain ({age} days old).")

    # No DNS records
    if domain_info.get("dns_records", 1) == 0:
        reasons.append("⚠️ Domain has no valid DNS records.")

    # HTTPS check
    if features.get("has_https") == 0:
        reasons.append("⚠️ Connection is not secure (HTTP instead of HTTPS).")

    # Final fallback
    if not reasons and is_phishing:
        reasons.append("⚠️ Multiple suspicious indicators detected suggesting phishing.")

    if not reasons and not is_phishing:
        reasons.append("✅ No strong phishing indicators detected.")

    return reasons
