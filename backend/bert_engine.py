from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
import torch
import re
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.abspath(
    os.path.join(BASE_DIR, "..", "model", "scam_distilbert_model")
)

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model directory not found: {MODEL_PATH}")

tokenizer = DistilBertTokenizerFast.from_pretrained(
    MODEL_PATH,
    local_files_only=True
)

model = DistilBertForSequenceClassification.from_pretrained(
    MODEL_PATH,
    local_files_only=True
)

model.eval()


def analyze_message(message: str):
    """
    Analyze a message and determine if it is phishing, suspicious, or safe.
    Uses BERT prediction + light heuristic keyword check.
    """

    # Preprocess
    text = str(message).lower()
    text = re.sub(r"[ \t]+", " ", text)

    # Heuristic keywords
    scam_keywords = [
        "win", "prize", "lottery", "verify", "account", "bank",
        "urgent", "click", "suspended", "password", "login"
    ]

    keyword_hits = sum(word in text for word in scam_keywords)

    # Model inference
    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding="max_length",
        max_length=256
    )

    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits

    prob = torch.softmax(logits, dim=-1)[0][1].item()
    prob_percent = round(prob * 100, 2)

    # Improved classification logic
    if prob >= 0.70:
        status = "PHISHING"

    elif prob >= 0.30 or (prob >= 0.20 and keyword_hits >= 2):
        status = "SUSPICIOUS"

    else:
        status = "SAFE"

    return {
        "status": status,
        "scam_probability": prob_percent
    }