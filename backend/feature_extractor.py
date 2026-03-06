import re
import math
import tldextract
from urllib.parse import urlparse, parse_qs

extractor = tldextract.TLDExtract(suffix_list_urls=None)

SUSPICIOUS_TLDS = ["xyz", "top", "click", "gq", "tk", "cfd", "buzz"]

SHORTENERS = [
    "bit.ly","tinyurl.com","t.co","goo.gl",
    "ow.ly","buff.ly","is.gd","soo.gd"
]

FREE_HOSTING = [
    "weebly","wixsite","github.io",
    "blogspot","wordpress","000webhost"
]

KEYWORDS = [
    "login","verify","update","secure",
    "bank","account","free","bonus",
    "confirm","signin","password"
]


def entropy(s):

    if len(s) == 0:
        return 0

    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]

    return -sum([p * math.log(p, 2) for p in prob])


def extract_url_features(url):

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    path = parsed.path

    query = parsed.query

    ext = extractor(url)

    url_length = len(url)

    num_dots = url.count(".")

    num_hyphens = url.count("-")

    num_subdomains = len(ext.subdomain.split(".")) if ext.subdomain else 0

    has_ip = 1 if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", url) else 0

    has_https = 1 if url.startswith("https://") else 0

    keyword_count = sum(1 for k in KEYWORDS if k in url.lower())

    url_entropy = entropy(url)

    domain_entropy = entropy(domain)

    digit_count = sum(c.isdigit() for c in url)

    digit_ratio = digit_count / max(url_length, 1)

    special_chars = sum(c in "@_?&=%" for c in url)

    query_param_count = len(parse_qs(query))

    tld = ext.suffix

    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    shortener_flag = 1 if domain in SHORTENERS else 0

    free_hosting_flag = 1 if any(h in domain for h in FREE_HOSTING) else 0

    repeated_chars = 1 if re.search(r"(.)\1{2,}", domain) else 0

    return {
        "url_length": url_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_subdomains": num_subdomains,
        "has_ip": has_ip,
        "has_https": has_https,
        "keyword_count": keyword_count,
        "url_entropy": url_entropy,
        "domain_entropy": domain_entropy,
        "digit_count": digit_count,
        "digit_ratio": digit_ratio,
        "special_chars": special_chars,
        "query_param_count": query_param_count,
        "suspicious_tld": suspicious_tld,
        "shortener_flag": shortener_flag,
        "free_hosting_flag": free_hosting_flag,
        "repeated_chars": repeated_chars,
        "path_length": len(path),
        "query_length": len(query)
    }


def get_feature_array(url):

    f = extract_url_features(url)

    f["url_entropy"] = round(f["url_entropy"], 4)
    f["domain_entropy"] = round(f["domain_entropy"], 4)
    f["digit_ratio"] = round(f["digit_ratio"], 4)

    return [
        f["url_length"],
        f["num_dots"],
        f["num_hyphens"],
        f["num_subdomains"],
        f["has_ip"],
        f["has_https"],
        f["keyword_count"],
        f["url_entropy"],
        f["domain_entropy"],
        f["digit_count"],
        f["digit_ratio"],
        f["special_chars"],
        f["query_param_count"],
        f["suspicious_tld"],
        f["shortener_flag"],
        f["free_hosting_flag"],
        f["repeated_chars"],
        f["path_length"],
        f["query_length"]
    ]
