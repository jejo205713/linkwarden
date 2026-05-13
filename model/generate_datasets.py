"""Deterministic synthetic-dataset generator for LinkWarden.

Produces:
- datasets/legitimate_dataset.csv (~300 rows)  label=0
- datasets/phishing_urls.csv     (~300 rows)   label=1

Phishing categories covered:
- fake bank portals (SBI/HDFC/ICICI/Axis/Kotak/etc.)
- UPI / payment scams (Paytm/PhonePe/GPay/BHIM)
- OTP scams (KYC / account-block lures)
- QR scams
- delivery / courier scams (IndiaPost/DTDC/Bluedart/FedEx/Bharat)
- typosquatting
- shortener-disguised
- IP-address-based phishing
- punycode / IDN homoglyphs
- Tamil Nadu localized scam patterns (govt impersonation)

Run: python model/generate_datasets.py
"""
from __future__ import annotations

import csv
import os
import random
from itertools import product

SEED = 1729
OUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "datasets"))


# ---------------------------------------------------------------------------
# Legitimate URLs
# ---------------------------------------------------------------------------

LEGIT_BASES = [
    # Indian govt / quasi-govt
    ("https://www.sbi.co.in", ["/web/personal-banking", "/web/business", "/web/nri", "/web/agri-rural"]),
    ("https://www.hdfcbank.com", ["/personal", "/sme", "/wholesale", "/htdocs/common/contactus.html"]),
    ("https://www.icicibank.com", ["/personal-banking", "/corporate-banking", "/nri-banking"]),
    ("https://www.axisbank.com", ["/retail", "/corporate", "/agri-and-rural"]),
    ("https://www.kotak.com", ["/en/personal-banking.html", "/en/business-banking.html"]),
    ("https://www.canarabank.com", ["/personal/", "/corporate/"]),
    ("https://www.pnbindia.in", ["/personal-banking.html", "/corporate-banking.html"]),
    ("https://www.unionbankofindia.co.in", ["/english/home.aspx"]),
    ("https://www.npci.org.in", ["/what-we-do/upi/product-overview", "/what-we-do/rupay"]),
    ("https://www.rbi.org.in", ["/Scripts/NotificationUser.aspx", "/Scripts/BS_PressReleaseDisplay.aspx"]),
    ("https://www.uidai.gov.in", ["/en/", "/en/my-aadhaar", "/en/contact-support.html"]),
    ("https://incometaxindia.gov.in", ["/", "/Pages/about-us/about-the-department.aspx"]),
    ("https://www.irctc.co.in", ["/nget/train-search", "/nget/profile/user-profile"]),
    ("https://www.indianpost.gov.in", ["/", "/postal/services.aspx"]),
    ("https://www.epfindia.gov.in", ["/site_en/index.php", "/site_en/contact_us.php"]),
    # TN-specific
    ("https://eservices.tn.gov.in", ["/", "/eservicesnew/"]),
    ("https://www.tn.gov.in", ["/department", "/scheme"]),
    ("https://chennaicorporation.gov.in", ["/", "/online-civic-services"]),
    ("https://tnreginet.gov.in", ["/portal/"]),
    # Telcos
    ("https://www.airtel.in", ["/recharge", "/postpaid", "/broadband"]),
    ("https://www.jio.com", ["/selfcare", "/postpaid", "/recharge"]),
    ("https://www.bsnl.co.in", ["/opencms/bsnl/BSNL/index.html"]),
    ("https://www.vi.com", ["/recharge", "/postpaid", "/prepaid"]),
    # Payments
    ("https://www.paytm.com", ["/recharge", "/electricity-bill-payment", "/mobile-recharge"]),
    ("https://www.phonepe.com", ["/business-solutions", "/about-us"]),
    ("https://pay.google.com", ["/about/", "/intl/en_in/about/"]),
    ("https://www.cred.club", ["/rewards", "/membership"]),
    ("https://www.mobikwik.com", ["/recharge", "/billpay"]),
    # E-commerce
    ("https://www.amazon.in", ["/dp/B08L5VZHMQ", "/gp/help/customer/display.html", "/your-orders"]),
    ("https://www.flipkart.com", ["/mobiles", "/fashion", "/account/orders"]),
    ("https://www.myntra.com", ["/men", "/women", "/kids"]),
    ("https://www.ajio.com", ["/c/men", "/c/women"]),
    # Travel / food
    ("https://www.makemytrip.com", ["/flights", "/hotels", "/holidays"]),
    ("https://www.bookmyshow.com", ["/explore/movies", "/explore/events"]),
    ("https://www.zomato.com", ["/bangalore", "/chennai", "/mumbai"]),
    ("https://www.swiggy.com", ["/restaurants", "/instamart"]),
    # Global tech
    ("https://www.google.com", ["/search?q=phishing", "/maps", "/about"]),
    ("https://www.youtube.com", ["/feed/trending", "/results?search_query=cybersecurity"]),
    ("https://www.microsoft.com", ["/en-in/microsoft-365", "/en-in/windows"]),
    ("https://www.apple.com", ["/in/iphone-15", "/in/macbook-air", "/in/support"]),
    ("https://www.netflix.com", ["/in/title/80100172", "/in/browse"]),
    ("https://www.linkedin.com", ["/feed", "/jobs", "/in/"]),
    ("https://twitter.com", ["/explore", "/home"]),
    ("https://www.instagram.com", ["/explore", "/explore/tags/india/"]),
    ("https://www.whatsapp.com", ["/business", "/security"]),
    ("https://www.cloudflare.com", ["/learning/security/threats/whaling", "/products/zero-trust"]),
    # News
    ("https://www.bbc.com", ["/news/world-asia-india", "/news/business"]),
    ("https://www.thehindu.com", ["/news/national", "/news/cities/chennai"]),
    ("https://timesofindia.indiatimes.com", ["/business", "/india"]),
    ("https://www.ndtv.com", ["/india-news", "/business"]),
    # Education
    ("https://www.iitm.ac.in", ["/academics", "/admissions"]),
    ("https://www.iisc.ac.in", ["/admissions", "/research"]),
    ("https://nptel.ac.in", ["/courses", "/about_nptel.html"]),
    ("https://swayam.gov.in", ["/explorer", "/about"]),
    # Dev tools
    ("https://github.com", ["/anthropics", "/explore", "/trending"]),
    ("https://stackoverflow.com", ["/questions/tagged/python", "/questions/tagged/security"]),
    ("https://chat.openai.com", ["/auth/login", "/c"]),
    ("https://claude.ai", ["/chats", "/account"]),
]


LEGIT_QUERY_TEMPLATES = [
    "?ref=homepage", "?utm_source=email", "?utm_campaign=newsletter",
    "?lang=en", "?lang=ta", "?lang=hi", "?page=1", "?page=2",
    "", "", "",  # weight toward no-query
]

LEGIT_PATH_EXTENSIONS = [
    "", "/about", "/help", "/contact", "/faq", "/privacy", "/terms",
    "/careers", "/news", "/blog", "/support",
]


def build_legitimate_rows() -> list[tuple[str, str, int]]:
    rng = random.Random(SEED + 1)
    rows: list[tuple[str, str, int]] = []

    # Base URLs as-is.
    for base, paths in LEGIT_BASES:
        for path in paths:
            url = base.rstrip("/") + path
            rows.append((url, "legitimate", 0))

    # Synthesize natural variations: same hosts, different paths/queries.
    # This expands realistic feature distribution (URL length, query count, etc.)
    # without inventing fake hosts.
    for base, _ in LEGIT_BASES:
        for _ in range(rng.randint(2, 4)):
            ext = rng.choice(LEGIT_PATH_EXTENSIONS)
            qry = rng.choice(LEGIT_QUERY_TEMPLATES)
            url = f"{base.rstrip('/')}{ext}{qry}"
            rows.append((url, "legitimate", 0))

    return rows


# ---------------------------------------------------------------------------
# Phishing URL templates
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = [
    "xyz", "top", "click", "gq", "tk", "cfd", "buzz", "zip", "monster",
    "sbs", "fit", "rest", "online", "site",
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "soo.gd",
]

INDIAN_BANK_BRANDS = [
    "sbi", "hdfc", "icici", "axis", "kotak", "canara", "pnb",
    "unionbank", "bobibank", "yesbank", "idfc", "federalbank",
    "indusind", "rblbank",
]

UPI_BRANDS = ["paytm", "phonepe", "gpay", "googlepay", "bhim", "mobikwik", "freecharge", "cred"]
COURIER_BRANDS = ["indiapost", "dtdc", "bluedart", "fedex", "dhl", "delhivery", "ekartlogistics", "shadowfax"]
GOVT_BRANDS = ["uidai", "incometax", "rbi", "epfo", "irctc", "tncrime", "tngov", "tnpolice"]

SCAM_LURES = [
    "kyc-update", "kyc-verify", "kyc-pending", "account-block", "account-suspended",
    "verify-now", "secure-login", "login-update", "password-reset",
    "refund-portal", "refund-claim", "tax-refund", "subsidy-claim",
    "bonus-claim", "cashback", "rewards", "winner-2024", "lottery-winner",
    "otp-verify", "otp-portal", "otp-bypass", "block-removal",
    "qr-payment", "qr-scan", "qr-claim",
    "courier-pending", "package-stuck", "delivery-failed", "customs-charge",
    "free-recharge", "free-data", "vaccine-register", "covid-aid",
]

PATH_SUFFIXES = [
    "/login", "/signin", "/auth", "/verify", "/portal", "/index.php",
    "/account/secure", "/cust/auth", "/m/login", "/wap/login.html",
    "/", "/home", "/secure", "/redirect",
]


def random_phish_path(rng: random.Random) -> str:
    """Build a noisy path that looks vaguely auth-related."""
    n = rng.randint(1, 3)
    parts = [rng.choice(["login", "auth", "verify", "secure", "id", "session", "u", "m"]) for _ in range(n)]
    return "/" + "/".join(parts) + rng.choice(PATH_SUFFIXES)


def random_query(rng: random.Random) -> str:
    keys = ["ref", "token", "session", "sid", "uid", "ts"]
    n = rng.randint(0, 2)
    if n == 0:
        return ""
    pairs = [f"{rng.choice(keys)}={rng.randint(10000, 9999999)}" for _ in range(n)]
    return "?" + "&".join(pairs)


def build_phishing_rows(rng: random.Random) -> list[tuple[str, str, int]]:
    rows: list[tuple[str, str, int]] = []

    # 1. Fake bank portals
    for brand, lure, tld in product(INDIAN_BANK_BRANDS, SCAM_LURES[:8], SUSPICIOUS_TLDS[:4]):
        if rng.random() > 0.18:
            continue
        url = f"http://{brand}-{lure}.{tld}{random_phish_path(rng)}{random_query(rng)}"
        rows.append((url, "phishing", 1))

    # 2. UPI / payment scams
    for brand, lure, tld in product(UPI_BRANDS, SCAM_LURES[8:18], SUSPICIOUS_TLDS):
        if rng.random() > 0.10:
            continue
        url = f"http://{brand}-{lure}.{tld}{random_phish_path(rng)}"
        rows.append((url, "phishing", 1))

    # 3. Delivery / courier scams (huge in 2024-25 India)
    for brand in COURIER_BRANDS:
        for lure in ["customs-charge", "delivery-failed", "package-stuck", "courier-pending", "address-update"]:
            tld = rng.choice(SUSPICIOUS_TLDS)
            url = f"http://{brand}-{lure}.{tld}/track?id={rng.randint(1000000, 9999999)}"
            rows.append((url, "phishing", 1))

    # 4. Govt impersonation
    for brand, lure, tld in product(GOVT_BRANDS, ["refund", "subsidy", "kyc", "verify", "claim"], SUSPICIOUS_TLDS):
        if rng.random() > 0.15:
            continue
        url = f"http://{brand}-{lure}.{tld}{random_phish_path(rng)}"
        rows.append((url, "phishing", 1))

    # 5. Typosquatting variants (insert/duplicate/swap letters)
    typo_targets = INDIAN_BANK_BRANDS + UPI_BRANDS + ["amazon", "flipkart", "paypal", "google", "apple", "microsoft"]
    for brand in typo_targets:
        # double-letter
        for i in range(1, len(brand) - 1):
            typo = brand[:i] + brand[i] + brand[i:]
            tld = rng.choice(SUSPICIOUS_TLDS)
            url = f"http://{typo}-secure.{tld}/login"
            rows.append((url, "phishing", 1))
            if len(rows) % 5 == 0:
                break

    # 6. Shortener-disguised
    for short in SHORTENERS:
        for _ in range(3):
            slug = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=rng.randint(5, 9)))
            url = f"http://{short}/{slug}"
            rows.append((url, "phishing", 1))

    # 7. IP-based
    for _ in range(15):
        ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        target = rng.choice(INDIAN_BANK_BRANDS + UPI_BRANDS)
        url = f"http://{ip}/{target}{random_phish_path(rng)}"
        rows.append((url, "phishing", 1))

    # 8. Subdomain-spoofing (real brand string in subdomain, fake parent)
    for brand in INDIAN_BANK_BRANDS[:6] + UPI_BRANDS[:4]:
        for tld in SUSPICIOUS_TLDS[:5]:
            url = f"http://login.{brand}.{rng.choice(['secure-portal', 'auth-verify', 'session-id'])}.{tld}/"
            rows.append((url, "phishing", 1))

    # 9. Punycode / IDN homoglyph (latin look-alikes for cyrillic 'а', 'е', 'о')
    homoglyph_map = [
        ("paypal", "xn--pypl-53dc3a"),
        ("apple", "xn--ppl-2na6c"),
        ("google", "xn--ggle-55da"),
        ("amazon", "xn--mzon-pra"),
        ("microsoft", "xn--mcrosoft-fya"),
    ]
    for _, ace in homoglyph_map:
        url = f"http://{ace}.com/login"
        rows.append((url, "phishing", 1))

    # 10. QR scam phrasing in URL itself
    for brand in UPI_BRANDS + ["bharatpe", "myamaha"]:
        url = f"http://qr-{brand}-payment.{rng.choice(SUSPICIOUS_TLDS)}/scan?amt={rng.randint(100, 50000)}"
        rows.append((url, "phishing", 1))

    # 11. Tamil Nadu localized lures
    tn_lures = [
        "tn-aadhaar-update", "tn-pan-link", "tn-rationcard-renew", "tn-electricity-refund",
        "tn-pension-verify", "tn-scholarship-2024", "tn-aavin-subsidy", "chennai-property-tax",
        "tn-employment-card", "tn-cmrf-claim",
    ]
    for lure in tn_lures:
        for tld in SUSPICIOUS_TLDS[:6]:
            url = f"http://{lure}.{tld}{random_phish_path(rng)}"
            rows.append((url, "phishing", 1))

    # 12. OTP-share lures (parameterized)
    for brand in INDIAN_BANK_BRANDS[:5] + UPI_BRANDS[:3]:
        url = f"http://otp-share-{brand}.{rng.choice(SUSPICIOUS_TLDS)}/share?otp=REQUIRED"
        rows.append((url, "phishing", 1))

    return rows


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main():
    rng = random.Random(SEED)

    legit = build_legitimate_rows()
    phish = build_phishing_rows(rng)

    # Dedupe within each class
    legit = list({r[0]: r for r in legit}.values())
    phish = list({r[0]: r for r in phish}.values())

    # Cross-class collision check (paranoia)
    legit_urls = {r[0] for r in legit}
    phish = [r for r in phish if r[0] not in legit_urls]

    os.makedirs(OUT_DIR, exist_ok=True)

    legit_path = os.path.join(OUT_DIR, "legitimate_dataset.csv")
    with open(legit_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "Type", "label"])
        w.writerows(legit)

    phish_path = os.path.join(OUT_DIR, "phishing_urls.csv")
    with open(phish_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "Type", "label"])
        w.writerows(phish)

    print(f"Wrote {len(legit)} legitimate rows -> {legit_path}")
    print(f"Wrote {len(phish)} phishing rows   -> {phish_path}")


if __name__ == "__main__":
    main()
