"""
korean_recognizer.py — Korean PII Validation Logic (Presidio-independent)
=========================================================================
Provides pure Python validators + optional Presidio recognizers:
  - validate_luhn(number)           — Credit/debit card Luhn check
  - validate_rrn_checksum(rrn)      — Korean RRN (주민등록번호) checksum
  - get_korean_recognizers()        — Presidio recognizers (when Presidio available)
"""

import logging
from typing import Optional, List

logger = logging.getLogger("scanner.korean_recognizer")


# ══════════════════════════════════════════════════════════════════════════════
# Pure Python Validators (no external dependencies)
# ══════════════════════════════════════════════════════════════════════════════

def validate_luhn(number) -> bool:
    """
    Standard Luhn algorithm for credit/debit card number validation.
    Accepts strings with or without hyphens/spaces.
    """
    if not isinstance(number, str):
        return False
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit

    return checksum % 10 == 0


def validate_rrn_checksum(rrn) -> bool:
    """
    Validate Korean 주민등록번호 (Resident Registration Number) checksum.
    Accepts 13 digits (with or without hyphen).
    
    Algorithm: weights [2,3,4,5,6,7,8,9,2,3,4,5] applied to digits 1-12.
    Check digit = (11 - sum % 11) % 10.
    """
    if not isinstance(rrn, str):
        return False
    digits_only = "".join(c for c in rrn if c.isdigit())
    if len(digits_only) != 13:
        return False

    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(digits_only[i]) * weights[i] for i in range(12))
    check = (11 - total % 11) % 10

    return check == int(digits_only[12])


# ══════════════════════════════════════════════════════════════════════════════
# Presidio Recognizers (loaded only when Presidio is available)
# ══════════════════════════════════════════════════════════════════════════════

def get_korean_recognizers() -> list:
    """
    Return Presidio PatternRecognizer instances for Korean PII entities.
    Returns empty list if Presidio is not available.
    """
    try:
        from presidio_analyzer import Pattern, PatternRecognizer

        class KoreanRRNRecognizer(PatternRecognizer):
            CONTEXT_WORDS = ["주민등록번호", "주민번호", "resident registration", "rrn", "주민등록", "신분증"]

            def __init__(self):
                patterns = [
                    Pattern("kr_rrn_hyphen",
                            r"\b(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-\u2013]\s?[1-4]\d{6}\b",
                            0.5),
                    Pattern("kr_rrn_plain",
                            r"\b(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[1-4]\d{6}\b",
                            0.4),
                ]
                super().__init__(supported_entity="KR_RRN", patterns=patterns,
                                 context=self.CONTEXT_WORDS, name="Korean_RRN_Recognizer",
                                 supported_language="en")

            def validate_result(self, pattern_text: str) -> Optional[bool]:
                # For Presidio, we'll keep the strict checksum but we could add a WeakRRN separately
                return validate_rrn_checksum(pattern_text)

        class KoreanWeakRRNRecognizer(PatternRecognizer):
            CONTEXT_WORDS = ["주민등록번호", "주민번호", "rrn", "주민등록"]

            def __init__(self):
                patterns = [
                    Pattern("kr_rrn_weak",
                            r"\b(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-\u2013]\s?[1-4]\d{6}\b",
                            0.35),
                ]
                super().__init__(supported_entity="KR_RRN_WEAK", patterns=patterns,
                                 context=self.CONTEXT_WORDS, name="Korean_Weak_RRN_Recognizer",
                                 supported_language="en")

        class KoreanPassportRecognizer(PatternRecognizer):
            CONTEXT_WORDS = ["여권", "여권번호", "passport", "passport number"]

            def __init__(self):
                patterns = [
                    Pattern("kr_passport_flexible", r"\b[A-Za-z][A-Za-z0-9]{8}\b", 0.4),
                    Pattern("kr_passport_flexible_new", r"\b[A-Za-z]{2}[A-Za-z0-9]{7}\b", 0.4),
                ]
                super().__init__(supported_entity="KR_PASSPORT", patterns=patterns,
                                 context=self.CONTEXT_WORDS, name="Korean_Passport_Recognizer",
                                 supported_language="en")

        class KoreanCardRecognizer(PatternRecognizer):
            CONTEXT_WORDS = ["카드번호", "카드", "신용카드", "체크카드", "credit card",
                             "card number", "visa", "mastercard", "삼성카드", "신한카드"]

            def __init__(self):
                patterns = [
                    Pattern("card_grouped", r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b", 0.5),
                    Pattern("card_continuous", r"\b[3-6]\d{12,18}\b", 0.3),
                ]
                super().__init__(supported_entity="KR_CARD_NUMBER", patterns=patterns,
                                 context=self.CONTEXT_WORDS, name="Korean_Card_Recognizer",
                                 supported_language="en")

            def validate_result(self, pattern_text: str) -> Optional[bool]:
                return validate_luhn(pattern_text)

        class KoreanPhoneRecognizer(PatternRecognizer):
            CONTEXT_WORDS = ["전화번호", "연락처", "핸드폰", "휴대폰", "phone", "mobile"]

            def __init__(self):
                patterns = [
                    Pattern("kr_mobile", r"\b01[016789][-.\s]?\d{3,4}[-.\s]?\d{4}\b", 0.5),
                    Pattern("kr_landline", r"\b0[2-6][1-5]?[-.\s]?\d{3,4}[-.\s]?\d{4}\b", 0.4),
                    Pattern("kr_intl", r"\+82[-.\s]?10[-.\s]?\d{4}[-.\s]?\d{4}\b", 0.6),
                ]
                super().__init__(supported_entity="KR_PHONE", patterns=patterns,
                                 context=self.CONTEXT_WORDS, name="Korean_Phone_Recognizer",
                                 supported_language="en")

        return [
            KoreanRRNRecognizer(),
            KoreanWeakRRNRecognizer(),
            KoreanPassportRecognizer(),
            KoreanCardRecognizer(),
            KoreanPhoneRecognizer(),
        ]

    except Exception:
        return []
