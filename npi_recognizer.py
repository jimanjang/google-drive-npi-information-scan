"""
npi_recognizer.py — NPI Validation Logic (Presidio-independent)
================================================================
Provides:
  1. validate_npi_luhn(npi) — Pure Python Luhn validation for NPI
  2. NPIRecognizer — Presidio PatternRecognizer (optional, used only when Presidio available)

The validator function is used directly by NativePatternMatcher when Presidio is unavailable.
"""

import logging
from typing import Optional

logger = logging.getLogger("scanner.npi_recognizer")


def validate_npi_luhn(npi) -> bool:
    """
    Validate a 10-digit NPI using the Luhn algorithm.
    
    Per CMS specification, the NPI is prefixed with '80840' to form
    a 15-digit number before applying the standard Luhn checksum.
    
    Args:
        npi: A string of exactly 10 digits (or digits-only string extracted from match).
        
    Returns:
        True if the NPI passes the Luhn check, False otherwise.
    """
    if not isinstance(npi, str):
        return False
    digits_only = "".join(c for c in npi if c.isdigit())
    if len(digits_only) != 10:
        return False

    # CMS standard: prepend '80840' to form 15-digit identifier
    prefixed = "80840" + digits_only
    digits = [int(d) for d in prefixed]

    # Luhn: traverse from right, double every second digit
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit

    return checksum % 10 == 0


# ── Presidio PatternRecognizer (loaded only when Presidio is available) ────────

def get_npi_recognizer():
    """
    Returns Presidio NPIRecognizer if Presidio is available, else None.
    Usage: recognizer = get_npi_recognizer() if using Presidio mode.
    """
    try:
        from presidio_analyzer import Pattern, PatternRecognizer

        class NPIRecognizer(PatternRecognizer):
            CONTEXT_WORDS = [
                "npi", "national provider", "provider identifier",
                "provider number", "provider id", "billing provider",
                "rendering provider", "cms", "medicare", "medicaid",
            ]

            def __init__(self):
                npi_pattern = Pattern(
                    name="npi_pattern_10digit",
                    regex=r"\b\d{10}\b",
                    score=0.3,
                )
                super().__init__(
                    supported_entity="NPI",
                    patterns=[npi_pattern],
                    context=self.CONTEXT_WORDS,
                    name="NPI_Recognizer",
                    supported_language="en",
                )

            def validate_result(self, pattern_text: str) -> Optional[bool]:
                return validate_npi_luhn(pattern_text)

        return NPIRecognizer()
    except Exception:
        return None
