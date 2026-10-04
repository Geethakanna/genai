"""
GuardianAI - PII Detection & Tokenization Engine (SecureGen)

Module 4 in the architecture. Scans text for sensitive values, replaces
each match with a reversible token, and hands the real values to the
Vault for encrypted storage. The agent only ever sees the tokenized text.

Design notes (avoiding known failure modes of AI-generated detectors):
  - Every pattern below is checked against real, correctly-formatted
    sample values in the accompanying test file — not just "looks right".
  - Card numbers use a real Luhn checksum, not just "16 digits", to
    reduce false positives on things like tracking numbers or IDs.
  - This module intentionally does NOT claim to catch every category
    from the taxonomy in one pass (health/legal context needs an NER
    model, not regex). It documents exactly what it covers so nobody
    downstream over-trusts it.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from enum import Enum


class PiiCategory(str, Enum):
    CREDIT_CARD = "credit_card"
    BANK_ACCOUNT_IFSC = "bank_account_ifsc"  # Indian IFSC-tagged accounts
    EMAIL = "email"
    PHONE = "phone"
    AADHAAR = "aadhaar"
    PAN_INDIA = "pan_india"  # Indian Income Tax PAN
    US_SSN = "us_ssn"
    API_KEY_GENERIC = "api_key_generic"
    AWS_ACCESS_KEY = "aws_access_key"
    IPV4 = "ipv4"


@dataclass(frozen=True)
class Match:
    category: PiiCategory
    original_value: str
    start: int
    end: int


@dataclass(frozen=True)
class TokenizedResult:
    text: str
    tokens: dict[str, Match]  # token_id -> the Match it replaced


def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 12:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


# Ordered list of (category, compiled pattern, optional validator).
# Order matters: more specific patterns (Aadhaar, PAN) are checked
# before generic ones to avoid a general digit-run swallowing them.
_PATTERNS: list[tuple[PiiCategory, re.Pattern, "callable | None"]] = [
    (
        PiiCategory.EMAIL,
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        None,
    ),
    (
        PiiCategory.AADHAAR,
        re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
        None,
    ),
    (
        PiiCategory.PAN_INDIA,
        re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        None,
    ),
    (
        PiiCategory.US_SSN,
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        None,
    ),
    (
        PiiCategory.CREDIT_CARD,
        re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        _luhn_check,
    ),
    (
        PiiCategory.BANK_ACCOUNT_IFSC,
        re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),  # Indian IFSC code
        None,
    ),
    (
        PiiCategory.AWS_ACCESS_KEY,
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        None,
    ),
    (
        PiiCategory.API_KEY_GENERIC,
        # Allows underscores/hyphens in the key body too — real keys
        # (e.g. Stripe's sk_test_51H8...) often have several segments.
        re.compile(r"\b(?:sk|pk|api|key)[-_][A-Za-z0-9_-]{16,}\b", re.IGNORECASE),
        None,
    ),
    (
        PiiCategory.PHONE,
        re.compile(r"\b(?:\+?\d{1,3}[\s-]?)?\d{10}\b"),
        None,
    ),
    (
        PiiCategory.IPV4,
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
        None,
    ),
]


def detect(text: str) -> list[Match]:
    """Find all PII matches in text. Later patterns skip ranges already
    claimed by an earlier (more specific) match."""
    claimed: list[tuple[int, int]] = []
    matches: list[Match] = []

    for category, pattern, validator in _PATTERNS:
        for m in pattern.finditer(text):
            start, end = m.start(), m.end()
            if any(start < c_end and end > c_start for c_start, c_end in claimed):
                continue
            value = m.group(0)
            if validator and not validator(value):
                continue
            matches.append(Match(category, value, start, end))
            claimed.append((start, end))

    matches.sort(key=lambda mtch: mtch.start)
    return matches


def tokenize(text: str, id_fn=None) -> TokenizedResult:
    """
    Replace every detected PII value with a reversible token of the form
    <<GUARDIANAI:<category>:<uuid>>>. Returns the tokenized text plus a
    map the caller should pass to a Vault for encrypted storage — this
    function does not touch the vault directly, keeping detection and
    storage independently testable.

    `id_fn(value) -> str` lets the caller derive a stable token id from the
    value (same value -> same token, so an agent can tell two mentions of one
    account apart from two different accounts). Without it a random id is used.
    """
    matches = detect(text)
    tokens: dict[str, Match] = {}
    # Rebuild the string right-to-left so earlier offsets stay valid.
    result = text
    for match in sorted(matches, key=lambda mtch: mtch.start, reverse=True):
        token_id = id_fn(match.original_value) if id_fn else uuid.uuid4().hex[:8]
        placeholder = f"<<GUARDIANAI:{match.category.value}:{token_id}>>"
        result = result[: match.start] + placeholder + result[match.end :]
        tokens[token_id] = match
    return TokenizedResult(text=result, tokens=tokens)


_DETOKEN_PATTERN = re.compile(r"<<GUARDIANAI:[a-z_]+:([a-f0-9]{8,16})>>")


def find_token_ids(text: str) -> list[str]:
    """Token ids referenced in `text`, in order of appearance, without duplicates."""
    return list(dict.fromkeys(_DETOKEN_PATTERN.findall(text)))


def detokenize(text: str, real_values: dict[str, str]) -> str:
    """
    Re-insert real values into previously tokenized text. `real_values`
    maps token_id -> the real string to substitute. Called only by the
    policy engine (Module 5), never directly by an agent-facing path.
    """

    def _replace(m: re.Match) -> str:
        token_id = m.group(1)
        return real_values.get(token_id, m.group(0))

    return _DETOKEN_PATTERN.sub(_replace, text)
