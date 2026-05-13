"""Indian-brand typosquatting detection — must catch the most common
UPI/bank impersonation patterns seen in 2024-2025 SMS scams."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from predictor import detect_typosquatting


def test_sbi_typo_detected():
    detected, brand, _ = detect_typosquatting("http://sbiii-secure.xyz/login")
    assert detected and brand == "sbi"


def test_paytm_typo_detected():
    detected, brand, _ = detect_typosquatting("http://paaytm-rewards.gq")
    assert detected and brand == "paytm"


def test_phonepe_typo_detected():
    detected, brand, _ = detect_typosquatting("http://phonpepe-cashback.tk")
    assert detected and brand == "phonepe"


def test_hdfc_typo_detected():
    detected, brand, _ = detect_typosquatting("http://hdffc-secure.click")
    assert detected and brand == "hdfc"


def test_legit_sbi_not_flagged():
    detected, _, _ = detect_typosquatting("https://www.sbi.co.in/web/personal-banking")
    assert not detected
