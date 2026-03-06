from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
import torch
import re
import os

# Get the directory where this file is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Path to your model folder (changed "models" -> "model")
MODEL_PATH = os.path.abspath(
    os.path.join(BASE_DIR, "..", "model", "scam_distilbert_model")
)

# Check if model directory exists
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model directory not found: {MODEL_PATH}")

# Load tokenizer and model from local files
tokenizer = DistilBertTokenizerFast.from_pretrained(
    MODEL_PATH,
    local_files_only=True
)

model = DistilBertForSequenceClassification.from_pretrained(
    MODEL_PATH,
    local_files_only=True
)

# Set model to evaluation mode
model.eval()

def analyze_message(message: str):
    """
    Analyze a message and determine if it is phishing, suspicious, or safe.
    Uses BERT prediction + Heuristic keyword override for better sensitivity.
    """

    # 1. Preprocess
    text = str(message).lower()
    text = re.sub(r"[ \t]+", " ", text)

    # 2. Heuristic Keyword Check
    scam_keywords = [
        'win', 'prize', 'lottery', 'verify', 'account', 'bank',
        'urgent', 'click here', 'suspended', 'password', 'login'
    ]
    is_keyword_match = any(word in text for word in scam_keywords)

    # 3. Model Inference
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

    # Get probability of being a scam (class 1)
    prob = torch.softmax(logits, dim=-1)[0][1].item()
    prob_percent = round(prob * 100, 2)

    # 4. Dynamic Thresholding Logic
    if prob >= 0.70:
        status = "PHISHING"
    elif prob >= 0.25 or is_keyword_match:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"

    return {
        "status": status,
        "scam_probability": prob_percent
    }
