import dns.resolver
from urllib.parse import urlparse

def get_dns_info(url):
    domain = urlparse(url).netloc
    if not domain:
        domain = url

    info = {
        "has_mx": "OFF",
        "has_ns": "OFF",
        "num_a": 0
    }

    try:
        answers = dns.resolver.resolve(domain, "A")
        info["num_a"] = len(answers)
    except Exception: pass

    try:
        dns.resolver.resolve(domain, "MX")
        info["has_mx"] = "ACTIVE"
    except Exception: pass

    try:
        dns.resolver.resolve(domain, "NS")
        info["has_ns"] = "ACTIVE"
    except Exception: pass

    return info
