"""Message scam analyzer.

Returns a structured response with explanations:

    {
        "status": "SAFE" | "SUSPICIOUS" | "PHISHING",
        "confidence_score": 0..100,
        "scam_probability": 0..100,
        "explanations": [str, ...],
        "triggered_rules": [str, ...],
        "matched_keywords": [str, ...],
        "detected_categories": [str, ...],
        "risk_factors": {
            "credential_phishing": 0..100,
            "money_lure":          0..100,
            "urgency_pressure":    0..100,
            "official_impersonation": 0..100,
        },
        "model_available": bool,
    }

DistilBERT is loaded lazily on the first request — the Flask app starts
even if the model directory is absent. In that case we fall back to a
heuristic-only verdict.
"""
from __future__ import annotations

import os
import re
import threading
from typing import Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "model", "scam_distilbert_model"))


# ---------------------------------------------------------------------------
# Keyword catalogue with categories
# ---------------------------------------------------------------------------

# (pattern, category) — pattern is a plain substring, lowercased before match.
# Categories drive the radar chart on /bert.
KEYWORDS: list[tuple[str, str]] = [
    # English credential phishing
    ("verify",            "credential_phishing"),
    ("login",             "credential_phishing"),
    ("password",          "credential_phishing"),
    ("re-login",          "credential_phishing"),
    ("re login",          "credential_phishing"),
    ("kyc",               "credential_phishing"),
    ("aadhaar",           "credential_phishing"),
    ("aadhar",            "credential_phishing"),
    ("pan card",          "credential_phishing"),
    ("otp",               "credential_phishing"),
    ("one time password", "credential_phishing"),
    ("captcha",           "credential_phishing"),

    # Money lures
    ("win",          "money_lure"),
    ("won",          "money_lure"),
    ("prize",        "money_lure"),
    ("lottery",      "money_lure"),
    ("cashback",     "money_lure"),
    ("bonus",        "money_lure"),
    ("refund",       "money_lure"),
    ("subsidy",      "money_lure"),
    ("rupay",        "money_lure"),
    ("upi",          "money_lure"),
    ("free",         "money_lure"),

    # Urgency / pressure
    ("urgent",         "urgency_pressure"),
    ("immediately",    "urgency_pressure"),
    ("within 24 hours","urgency_pressure"),
    ("expires today",  "urgency_pressure"),
    ("last chance",    "urgency_pressure"),
    ("blocked",        "urgency_pressure"),
    ("frozen",         "urgency_pressure"),
    ("suspended",      "urgency_pressure"),
    ("deactivat",      "urgency_pressure"),

    # Official impersonation
    ("rbi",          "official_impersonation"),
    ("npci",         "official_impersonation"),
    ("uidai",        "official_impersonation"),
    ("income tax",   "official_impersonation"),
    ("pension",      "official_impersonation"),
    ("scholarship",  "official_impersonation"),
    ("police",       "official_impersonation"),
    ("courier",      "official_impersonation"),
    ("customs",      "official_impersonation"),
    ("delivery",     "official_impersonation"),

    # Hindi (transliterated)
    ("inaam", "money_lure"),
    ("jeet",  "money_lure"),
    ("paisa", "money_lure"),
    ("khata", "credential_phishing"),
    ("band ho", "urgency_pressure"),
    ("turant", "urgency_pressure"),

    # Hindi (Devanagari)
    ("इनाम",     "money_lure"),
    ("जीत",      "money_lure"),
    ("पुरस्कार",  "money_lure"),
    ("बैंक",     "credential_phishing"),
    ("खाता",     "credential_phishing"),
    ("ओटीपी",    "credential_phishing"),
    ("तुरंत",    "urgency_pressure"),
    ("बंद",      "urgency_pressure"),
    ("ब्लॉक",   "urgency_pressure"),

    # Tamil (transliterated)
    ("parisu",     "money_lure"),
    ("vetri",      "money_lure"),
    ("vangi",      "credential_phishing"),
    ("kanaku",     "credential_phishing"),
    ("muddakkam",  "urgency_pressure"),
    ("kappaattu",  "urgency_pressure"),
    ("kavalai",    "urgency_pressure"),
    ("aadhar number", "credential_phishing"),
    ("kadan",      "money_lure"),

    # Tamil (Tamil script) — 20+ phrases per spec
    ("பரிசு",                          "money_lure"),
    ("வெற்றி",                         "money_lure"),
    ("லாட்டரி",                         "money_lure"),
    ("பணம்",                            "money_lure"),
    ("பணம் திரும்ப",                    "money_lure"),
    ("கடன்",                            "money_lure"),
    ("வங்கி",                            "credential_phishing"),
    ("கணக்கு",                          "credential_phishing"),
    ("கடவுச்சொல்",                       "credential_phishing"),
    ("ஓடிபி",                           "credential_phishing"),
    ("ஆதார்",                           "credential_phishing"),
    ("உங்கள் கணக்கு தடுக்கப்பட்டது",      "urgency_pressure"),
    ("கணக்கு முடக்கப்பட்டது",            "urgency_pressure"),
    ("OTP பகிர வேண்டாம்",                "official_impersonation"),
    ("உடனே",                            "urgency_pressure"),
    ("விரைவில்",                         "urgency_pressure"),
    ("முடக்கம்",                         "urgency_pressure"),
    ("கைதுசெய்யப்படுவீர்கள்",             "official_impersonation"),
    ("காவல்துறை",                        "official_impersonation"),
    ("நீதிமன்றம்",                       "official_impersonation"),
    ("கூரியர்",                          "official_impersonation"),
    ("சுங்கம்",                          "official_impersonation"),
]


URL_PATTERN = re.compile(r"https?://\S+", re.IGNORECASE)
PHONE_PATTERN = re.compile(r"\b(?:\+?\d{1,3}[-\s]?)?\d{10}\b")


# ---------------------------------------------------------------------------
# Lazy DistilBERT loader
# ---------------------------------------------------------------------------

_model_lock = threading.Lock()
_bert_state: dict = {"loaded": False, "tokenizer": None, "model": None, "available": False}


def _ensure_bert_loaded() -> bool:
    """Try to load DistilBERT once; remember success/failure forever after.

    Returns True if the model is usable for inference, False otherwise.
    The Flask app must remain functional in the False case.
    """
    if _bert_state["loaded"]:
        return _bert_state["available"]

    with _model_lock:
        if _bert_state["loaded"]:
            return _bert_state["available"]
        _bert_state["loaded"] = True

        if not os.path.isdir(MODEL_PATH):
            print(f"[bert_engine] model dir not found at {MODEL_PATH} — using heuristic-only mode")
            return False

        try:
            from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification  # noqa: WPS433
            tok = DistilBertTokenizerFast.from_pretrained(MODEL_PATH, local_files_only=True)
            mdl = DistilBertForSequenceClassification.from_pretrained(MODEL_PATH, local_files_only=True)
            mdl.eval()
            _bert_state["tokenizer"] = tok
            _bert_state["model"] = mdl
            _bert_state["available"] = True
            print("[bert_engine] DistilBERT loaded.")
            return True
        except Exception as exc:  # noqa: BLE001
            print(f"[bert_engine] failed to load DistilBERT ({exc}) — heuristic-only mode")
            return False


def _bert_score(message: str) -> Optional[float]:
    """Return P(scam) in [0,1] or None if model unavailable."""
    if not _ensure_bert_loaded():
        return None
    try:
        import torch  # noqa: WPS433
        tok = _bert_state["tokenizer"]
        mdl = _bert_state["model"]
        inputs = tok(message, return_tensors="pt", truncation=True, padding="max_length", max_length=256)
        with torch.no_grad():
            logits = mdl(**inputs).logits
        probs = torch.softmax(logits, dim=-1)[0]
        # Assume class 1 = scam.
        return float(probs[1].item())
    except Exception as exc:  # noqa: BLE001
        print(f"[bert_engine] inference failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Heuristic analysis
# ---------------------------------------------------------------------------

def _heuristic_analysis(message: str) -> dict:
    """Compute keyword hits, categories, embedded URLs/phones, and a score."""
    text = message  # case-sensitive for non-Latin; we lowercase for ascii match below
    text_lower = text.lower()

    matched: list[str] = []
    categories_hit: dict[str, int] = {}
    for pattern, category in KEYWORDS:
        # ASCII keywords match against lowercased text; non-ASCII match raw.
        haystack = text_lower if pattern.isascii() else text
        if pattern in haystack:
            matched.append(pattern)
            categories_hit[category] = categories_hit.get(category, 0) + 1

    urls = URL_PATTERN.findall(text)
    phones = PHONE_PATTERN.findall(text)

    # Heuristic score: weight categories.
    weights = {
        "credential_phishing": 18,
        "money_lure": 12,
        "urgency_pressure": 14,
        "official_impersonation": 10,
    }
    score = 0
    for cat, n in categories_hit.items():
        score += weights.get(cat, 8) * min(n, 3)
    if urls:
        score += min(20, 10 * len(urls))
    if phones:
        score += 6
    score = max(0, min(100, score))

    risk_factors = {cat: min(100, n * 35) for cat, n in categories_hit.items()}
    for cat in ("credential_phishing", "money_lure", "urgency_pressure", "official_impersonation"):
        risk_factors.setdefault(cat, 0)

    return {
        "matched_keywords": matched,
        "categories_hit": categories_hit,
        "urls_in_message": urls,
        "phones_in_message": phones,
        "heuristic_score": score,
        "risk_factors": risk_factors,
    }


def _build_explanations(heur: dict, bert_prob: Optional[float]) -> list[str]:
    out = []
    for cat, n in heur["categories_hit"].items():
        label = cat.replace("_", " ").title()
        out.append(f"{label}: {n} matching phrase(s) detected.")
    if heur["urls_in_message"]:
        out.append(f"Contains {len(heur['urls_in_message'])} embedded URL(s) — common scam delivery pattern.")
    if heur["phones_in_message"]:
        out.append("Phone number embedded in message body (typical of scam callbacks).")
    if bert_prob is not None:
        out.append(f"DistilBERT scam-classifier probability: {bert_prob*100:.1f}%.")
    else:
        out.append("DistilBERT model not loaded — heuristic-only verdict.")
    return out


def _build_triggered_rules(heur: dict, bert_prob: Optional[float]) -> list[str]:
    rules = []
    for cat in heur["categories_hit"]:
        rules.append(f"CATEGORY_{cat.upper()}")
    if heur["urls_in_message"]:
        rules.append("EMBEDDED_URL")
    if heur["phones_in_message"]:
        rules.append("EMBEDDED_PHONE")
    if bert_prob is not None and bert_prob >= 0.7:
        rules.append("BERT_HIGH_CONFIDENCE")
    return rules


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_message(message: str) -> dict:
    if not isinstance(message, str):
        message = str(message or "")
    message = message.strip()

    if not message:
        return {
            "status": "SAFE",
            "confidence_score": 0,
            "scam_probability": 0,
            "explanations": ["Empty message."],
            "triggered_rules": [],
            "matched_keywords": [],
            "detected_categories": [],
            "risk_factors": {
                "credential_phishing": 0,
                "money_lure": 0,
                "urgency_pressure": 0,
                "official_impersonation": 0,
            },
            "model_available": _ensure_bert_loaded(),
        }

    heur = _heuristic_analysis(message)
    bert_prob = _bert_score(message)

    if bert_prob is not None:
        # Blend BERT with heuristic — BERT dominates but heuristic can lift it.
        combined = max(bert_prob * 100, heur["heuristic_score"] * 0.6 + bert_prob * 60)
    else:
        combined = float(heur["heuristic_score"])

    combined = max(0.0, min(100.0, combined))

    if combined >= 65:
        status = "PHISHING"
    elif combined >= 30:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"

    return {
        "status": status,
        "confidence_score": round(combined, 2),
        "scam_probability": round((bert_prob or heur["heuristic_score"] / 100) * 100, 2),
        "explanations": _build_explanations(heur, bert_prob),
        "triggered_rules": _build_triggered_rules(heur, bert_prob),
        "matched_keywords": heur["matched_keywords"],
        "detected_categories": list(heur["categories_hit"].keys()),
        "risk_factors": heur["risk_factors"],
        "model_available": bert_prob is not None,
    }
