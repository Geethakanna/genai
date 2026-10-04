"""
Real tests for the PII detector — run with: pytest tests/test_pii_detector.py

These use values that are *structurally* valid for their format
(a real Luhn-valid test card number, a correctly shaped IFSC code,
a syntactically valid PAN) but are standard, publicly-documented
test/example values, not anyone's real data.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from guardianai.detection.pii_detector import (  # noqa: E402
    PiiCategory,
    detect,
    detokenize,
    tokenize,
)


def test_detects_email():
    matches = detect("Contact me at jane.doe@example.com for details.")
    assert any(m.category == PiiCategory.EMAIL for m in matches)


def test_detects_valid_luhn_card_and_rejects_invalid():
    # 4111111111111111 is the standard publicly-documented Visa test number.
    valid = detect("Card: 4111111111111111")
    assert any(m.category == PiiCategory.CREDIT_CARD for m in valid)

    # Same length, fails Luhn -> should NOT be flagged as a card.
    invalid = detect("Order ref: 1234567890123456")
    assert not any(m.category == PiiCategory.CREDIT_CARD for m in invalid)


def test_detects_indian_ifsc_and_pan_formats():
    matches = detect("IFSC: HDFC0001234, PAN: ABCDE1234F")
    categories = {m.category for m in matches}
    assert PiiCategory.BANK_ACCOUNT_IFSC in categories
    assert PiiCategory.PAN_INDIA in categories


def test_detects_aws_key_and_generic_api_key():
    matches = detect("key=sk_test_51H8xyzabcdefghij AKIAABCDEFGHIJKLMNOP")
    categories = {m.category for m in matches}
    assert PiiCategory.AWS_ACCESS_KEY in categories
    assert PiiCategory.API_KEY_GENERIC in categories


def test_tokenize_and_detokenize_round_trip():
    original = "My email is jane.doe@example.com and card is 4111111111111111."
    result = tokenize(original)

    assert "jane.doe@example.com" not in result.text
    assert "4111111111111111" not in result.text
    assert len(result.tokens) == 2

    real_values = {
        token_id: match.original_value for token_id, match in result.tokens.items()
    }
    restored = detokenize(result.text, real_values)
    assert restored == original


def test_no_false_positive_on_plain_sentence():
    matches = detect("The meeting is scheduled for next Tuesday at the office.")
    assert matches == []


if __name__ == "__main__":
    import traceback

    tests = [
        test_detects_email,
        test_detects_valid_luhn_card_and_rejects_invalid,
        test_detects_indian_ifsc_and_pan_formats,
        test_detects_aws_key_and_generic_api_key,
        test_tokenize_and_detokenize_round_trip,
        test_no_false_positive_on_plain_sentence,
    ]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            print(f"PASS: {t.__name__}")
            passed += 1
        except AssertionError:
            print(f"FAIL: {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
