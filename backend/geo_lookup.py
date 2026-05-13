"""Resolve a URL's hostname to IP, country, city, ASN, and ISP via ip-api.com.

Free tier: ~45 req/min, no API key, HTTP only.
Returns a stable shape on every call — never raises.
"""
from __future__ import annotations

import requests
from urllib.parse import urlparse


_FALLBACK = {
    "ip": "—",
    "country": "Unknown",
    "city": "Unknown",
    "lat": 0.0,
    "lon": 0.0,
    "asn": "Unknown",
    "isp": "Unknown",
    "org": "Unknown",
    "ok": False,
}

_FIELDS = "status,country,city,lat,lon,query,as,isp,org"


def lookup_geo(url: str) -> dict:
    parsed = urlparse(url)
    netloc = parsed.netloc or url
    domain = netloc.split(":")[0].strip()
    if not domain:
        return dict(_FALLBACK)

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{domain}",
            params={"fields": _FIELDS},
            timeout=5,
        )
        data = resp.json()
        if data.get("status") != "success":
            return {**_FALLBACK, "ip": domain}
        return {
            "ip": data.get("query", domain),
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "lat": float(data.get("lat", 0.0)),
            "lon": float(data.get("lon", 0.0)),
            "asn": data.get("as", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "org": data.get("org", "Unknown"),
            "ok": True,
        }
    except Exception:
        return dict(_FALLBACK)