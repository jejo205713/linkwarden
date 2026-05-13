"""Lazy model loader with safe fallback if the artefact is missing/corrupt."""
import os
import threading

import joblib

_lock = threading.Lock()
_artefact = None
_load_attempted = False


def _model_path() -> str:
    return os.path.join(os.path.dirname(__file__), "..", "model", "phishing_model.pkl")


def get_model_artefact():
    """Return the dict {classifier, anomaly, feature_names} or None on failure."""
    global _artefact, _load_attempted
    if _artefact is not None:
        return _artefact

    with _lock:
        if _artefact is not None:
            return _artefact
        if _load_attempted:
            return None
        _load_attempted = True
        try:
            artefact = joblib.load(_model_path())
        except Exception as exc:  # noqa: BLE001
            print(f"[model_loader] Could not load phishing model: {exc}")
            return None

        # Validate v2 shape; if a stale v1 (raw model) is found, refuse.
        if not isinstance(artefact, dict) or "classifier" not in artefact:
            print("[model_loader] Stale model artefact format — please re-run model/train_model.py")
            return None

        _artefact = artefact
        return _artefact


# Backwards-compat shim so old call sites don't crash. Returns the calibrated
# classifier, or None.
def get_model():
    art = get_model_artefact()
    return art["classifier"] if art else None
