"""Predictor contract & sign tests for the supervised classifier."""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))


def _analyze_with_proba(proba: float):
    """Run analyze_url with a stub classifier returning P(phish) = proba."""
    fake_clf = MagicMock()
    fake_clf.predict_proba.return_value = [[1 - proba, proba]]
    fake_iforest = MagicMock()
    fake_iforest.decision_function.return_value = [0.0]

    fake_artefact = {
        "classifier": fake_clf,
        "anomaly": fake_iforest,
        "feature_names": [],
        "version": 2,
    }

    with patch('predictor.get_model_artefact', return_value=fake_artefact), \
         patch('predictor.expand_url', return_value=("https://example.org/", 0)), \
         patch('predictor.get_domain_info', return_value={"age_days": 1000, "registrar": "Example"}):
        from predictor import analyze_url
        return analyze_url("https://example.org/")


def test_high_phish_proba_yields_phishing_status():
    result = _analyze_with_proba(0.95)
    assert result["status"] == "PHISHING"
    assert result["confidence_score"] >= 65


def test_low_phish_proba_yields_safe_status():
    result = _analyze_with_proba(0.02)
    assert result["status"] == "SAFE"
    assert result["confidence_score"] < 40


def test_response_contract_keys_present():
    result = _analyze_with_proba(0.5)
    for key in ("status", "confidence_score", "reasons", "triggered_rules",
                "risk_factors", "model", "expanded_url", "redirect_count"):
        assert key in result, f"Missing key: {key}"
    for axis in ("url_structure", "domain_trust", "social_engineering", "technical_obfuscation"):
        assert axis in result["risk_factors"]
    assert isinstance(result["model"]["phishing_probability"], float)
