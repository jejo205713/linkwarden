"""URL feature extraction for LinkWarden.

Returns a fixed-order numeric vector via ``get_feature_array`` and a labelled
dict via ``extract_url_features``. The order in ``FEATURE_NAMES`` MUST match
the order in ``get_feature_array`` — this is the contract the trained model
relies on.
"""
from __future__ import annotations

import math
import os
import re
from urllib.parse import urlparse, parse_qs, unquote

import tldextract


_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "linkwarden-tldextract")
extractor = tldextract.TLDExtract(cache_dir=_CACHE_DIR)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "gq", "tk", "cfd", "buzz", "zip", "monster",
    "sbs", "fit", "rest", "online", "site", "country", "stream", "win",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "soo.gd", "shorturl.at", "rb.gy", "cutt.ly",
}

FREE_HOSTING = {
    "weebly", "wixsite", "github.io", "blogspot", "wordpress",
    "000webhost", "netlify.app", "vercel.app", "glitch.me",
    "repl.co", "pages.dev",
}

# Generic fishing/auth-lure keywords (English).
GENERIC_KEYWORDS = [
    "login", "verify", "update", "secure", "bank", "account",
    "free", "bonus", "confirm", "signin", "password", "credential",
    "wallet", "billing", "session", "validate",
]

# India-specific scam vocabulary frequently seen in URL paths/hosts.
UPI_LURE_KEYWORDS = [
    "upi", "kyc", "otp", "aadhaar", "pan", "rupay", "bhim",
    "refund", "subsidy", "cashback", "bonus", "lottery",
    "courier", "delivery", "package", "customs",
]

# ASCII characters that share visual shapes with common Latin letters.
# Presence of any of these in a hostname is a strong homoglyph signal.
HOMOGLYPH_CHARS = set("аеоԁсіһухлn")  # Cyrillic look-alikes, etc.


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def _safe_extract(url: str):
    try:
        return extractor(url)
    except Exception:
        # tldextract can crash on extreme garbage; fall back to a stub.
        class _Stub:
            subdomain = ""
            domain = ""
            suffix = ""
        return _Stub()


def _has_punycode(host: str) -> int:
    return 1 if "xn--" in host.lower() else 0


def _has_homoglyph(host: str) -> int:
    return 1 if any(ch in HOMOGLYPH_CHARS for ch in host) else 0


def _has_unicode(host: str) -> int:
    """Any non-ASCII character (rare for legit Indian English-language sites)."""
    try:
        host.encode("ascii")
        return 0
    except UnicodeEncodeError:
        return 1


def _percent_encoded_count(url: str) -> int:
    return len(re.findall(r"%[0-9A-Fa-f]{2}", url))


def _has_at_symbol(url: str) -> int:
    return 1 if "@" in url else 0


def _port_specified(parsed) -> int:
    # urlparse(...).port raises on malformed netloc — guard it.
    try:
        return 1 if parsed.port else 0
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "url_length",
    "num_dots",
    "num_hyphens",
    "num_subdomains",
    "has_ip",
    "has_https",
    "keyword_count",
    "url_entropy",
    "domain_entropy",
    "digit_count",
    "digit_ratio",
    "special_chars",
    "query_param_count",
    "suspicious_tld",
    "shortener_flag",
    "free_hosting_flag",
    "repeated_chars",
    "path_length",
    "query_length",
    # Newly added in the hardening pass.
    "punycode_flag",
    "homoglyph_flag",
    "unicode_in_host",
    "percent_encoded_count",
    "has_at_symbol",
    "port_specified",
    "upi_keyword_count",
    "subdomain_depth",
    "longest_token_length",
    "host_length",
]


def extract_url_features(url: str) -> dict:
    """Return a labelled feature dict. Always succeeds — never raises on garbage."""
    if not isinstance(url, str):
        url = str(url)

    # Defensive parsing — never crash, even on totally malformed input.
    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse("")

    host = (parsed.netloc or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    decoded = unquote(url)

    ext = _safe_extract(url)

    url_length = len(url)
    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_subdomains = len([p for p in (ext.subdomain or "").split(".") if p])

    has_ip = 1 if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", host) else 0
    has_https = 1 if url.lower().startswith("https://") else 0

    keyword_count = sum(1 for k in GENERIC_KEYWORDS if k in decoded.lower())
    upi_keyword_count = sum(1 for k in UPI_LURE_KEYWORDS if k in decoded.lower())

    url_entropy = shannon_entropy(url)
    domain_entropy = shannon_entropy(host)

    digit_count = sum(c.isdigit() for c in url)
    digit_ratio = digit_count / max(url_length, 1)

    special_chars = sum(c in "@_?&=%" for c in url)
    query_param_count = len(parse_qs(query))

    tld = (ext.suffix or "").lower().split(".")[-1]
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    shortener_flag = 1 if any(s in host for s in SHORTENERS) else 0
    free_hosting_flag = 1 if any(h in host for h in FREE_HOSTING) else 0
    repeated_chars = 1 if re.search(r"(.)\1{2,}", host) else 0

    punycode_flag = _has_punycode(host)
    homoglyph_flag = _has_homoglyph(host)
    unicode_in_host = _has_unicode(host)
    percent_encoded_count = _percent_encoded_count(url)
    has_at_symbol = _has_at_symbol(url)
    port_specified = _port_specified(parsed)
    subdomain_depth = num_subdomains

    tokens = re.split(r"[\.\-_/]", url)
    longest_token_length = max((len(t) for t in tokens if t), default=0)

    return {
        "url_length": url_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_subdomains": num_subdomains,
        "has_ip": has_ip,
        "has_https": has_https,
        "keyword_count": keyword_count,
        "url_entropy": round(url_entropy, 4),
        "domain_entropy": round(domain_entropy, 4),
        "digit_count": digit_count,
        "digit_ratio": round(digit_ratio, 4),
        "special_chars": special_chars,
        "query_param_count": query_param_count,
        "suspicious_tld": suspicious_tld,
        "shortener_flag": shortener_flag,
        "free_hosting_flag": free_hosting_flag,
        "repeated_chars": repeated_chars,
        "path_length": len(path),
        "query_length": len(query),
        "punycode_flag": punycode_flag,
        "homoglyph_flag": homoglyph_flag,
        "unicode_in_host": unicode_in_host,
        "percent_encoded_count": percent_encoded_count,
        "has_at_symbol": has_at_symbol,
        "port_specified": port_specified,
        "upi_keyword_count": upi_keyword_count,
        "subdomain_depth": subdomain_depth,
        "longest_token_length": longest_token_length,
        "host_length": len(host),
    }


def get_feature_array(url: str) -> list:
    """Numeric vector in FEATURE_NAMES order — required by the trained model."""
    f = extract_url_features(url)
    return [f[name] for name in FEATURE_NAMES]
