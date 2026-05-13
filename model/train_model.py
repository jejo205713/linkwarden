"""Train the supervised phishing classifier.

Pipeline:
1. Load both labelled datasets (legit + phishing).
2. Extract numeric features.
3. Train an 80/20 stratified split RandomForest.
4. Calibrate probabilities (sigmoid, prefit) on a held-out slice.
5. Train an Isolation Forest on legitimate-only features as a SECONDARY anomaly
   signal (used by the predictor for low-confidence cases).
6. Save both artefacts plus a JSON metrics report.

Outputs:
- model/phishing_model.pkl    -> dict with keys: classifier, anomaly, feature_names
- model/training_metrics.json -> precision/recall/f1/auc + feature importances
"""
from __future__ import annotations

import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from feature_extractor import FEATURE_NAMES, get_feature_array  # noqa: E402


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "datasets"))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")
METRICS_PATH = os.path.join(BASE_DIR, "training_metrics.json")

RANDOM_STATE = 42


def _load_labelled_dataset() -> pd.DataFrame:
    legit = pd.read_csv(os.path.join(DATASETS_DIR, "legitimate_dataset.csv"))
    phish = pd.read_csv(os.path.join(DATASETS_DIR, "phishing_urls.csv"))

    for df, name, expected in [(legit, "legitimate", 0), (phish, "phishing", 1)]:
        if "url" not in df.columns or len(df) == 0:
            raise RuntimeError(f"{name}_dataset.csv is empty or malformed")
        if "label" not in df.columns:
            df["label"] = expected

    combined = pd.concat([legit, phish], ignore_index=True)
    combined = combined.dropna(subset=["url"]).drop_duplicates(subset=["url"])
    return combined


def _featurize(urls: list[str]) -> tuple[np.ndarray, list[str]]:
    rows = []
    kept = []
    for url in urls:
        try:
            rows.append(get_feature_array(str(url)))
            kept.append(url)
        except Exception as exc:  # noqa: BLE001
            print(f"  skipped {url!r}: {exc}")
    return np.asarray(rows, dtype=float), kept


def train() -> None:
    print("Loading labelled datasets...")
    df = _load_labelled_dataset()
    print(f"  total rows: {len(df)} (label distribution: {df['label'].value_counts().to_dict()})")

    print("Extracting features...")
    X, kept = _featurize(df["url"].tolist())
    df = df[df["url"].isin(kept)].reset_index(drop=True)
    y = df["label"].astype(int).to_numpy()

    if len(np.unique(y)) < 2:
        raise RuntimeError("Both classes must be present after feature extraction.")

    print("Splitting train/test (stratified 80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=RANDOM_STATE
    )

    print("Training RandomForest...")
    base_clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )
    base_clf.fit(X_train, y_train)

    print("Calibrating probabilities (sigmoid, cv=3)...")
    calibrated = CalibratedClassifierCV(base_clf, method="sigmoid", cv=3)
    calibrated.fit(X_train, y_train)

    # Evaluate
    y_pred = calibrated.predict(X_test)
    y_proba = calibrated.predict_proba(X_test)[:, 1]
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="binary", zero_division=0
    )
    try:
        auc = roc_auc_score(y_test, y_proba)
    except ValueError:
        auc = 0.0
    cm = confusion_matrix(y_test, y_pred).tolist()

    print("\nClassification report:")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"], zero_division=0))

    # Feature importance (from the underlying RandomForest fit on full training data)
    importance_pairs = sorted(
        zip(FEATURE_NAMES, base_clf.feature_importances_.tolist()),
        key=lambda kv: kv[1],
        reverse=True,
    )

    print("Top 10 feature importances:")
    for name, imp in importance_pairs[:10]:
        print(f"  {name:30s} {imp:.4f}")

    # Secondary signal: IsolationForest on the *legitimate* class only.
    print("Training secondary IsolationForest on legitimate class...")
    legit_X = X[y == 0]
    iforest = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=RANDOM_STATE,
    )
    iforest.fit(legit_X)

    artefact = {
        "classifier": calibrated,
        "anomaly": iforest,
        "feature_names": list(FEATURE_NAMES),
        "version": 2,
    }
    joblib.dump(artefact, MODEL_PATH)
    print(f"\nModel artefact saved -> {MODEL_PATH}")

    metrics = {
        "test_precision": float(precision),
        "test_recall": float(recall),
        "test_f1": float(f1),
        "test_auc": float(auc),
        "confusion_matrix": cm,
        "test_set_size": int(len(y_test)),
        "train_set_size": int(len(y_train)),
        "feature_importances": dict(importance_pairs),
        "feature_names": list(FEATURE_NAMES),
    }
    with open(METRICS_PATH, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)
    print(f"Metrics report saved -> {METRICS_PATH}")


if __name__ == "__main__":
    train()
