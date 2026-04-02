"""
scanner_engine.py — PII Analysis Engine (Python-Native + Optional Presidio)
============================================================================
Two-tier design:
  1. PRESIDIO MODE: Full Presidio + spaCy engine (requires VC++ Redistributable)
  2. NATIVE MODE:   Pure Python pattern matching (no C extensions required)
                    Automatically activated when Presidio/spaCy is unavailable.

Both modes support NPI (Luhn), Korean PII (RRN, passport, card, phone),
credit cards, email addresses, phone numbers, US SSN, and more.
"""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple

from config import ScanConfig
from npi_recognizer import validate_npi_luhn
from korean_recognizer import validate_rrn_checksum, validate_luhn

logger = logging.getLogger("scanner.engine")


# ── Result Types ───────────────────────────────────────────────────────────────

@dataclass
class ScanFinding:
    """A single detected PII entity within a file."""
    entity_type: str
    confidence: float
    start: int
    end: int
    masked_value: str   # Masked — raw PII never stored


@dataclass
class FileScanResult:
    """Complete scan result for one file."""
    file_id: str
    file_name: str
    file_path: str
    mime_type: str
    modified_time: str
    total_chars: int = 0
    findings: List[ScanFinding] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def risk_score(self) -> float:
        if not self.findings:
            return 0.0
        return max(f.confidence for f in self.findings)

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 0.85: return "CRITICAL"
        if score >= 0.70: return "HIGH"
        if score >= 0.50: return "MEDIUM"
        if score > 0.0:   return "LOW"
        return "CLEAN"

    @property
    def entity_summary(self) -> dict:
        summary: dict = {}
        for f in self.findings:
            summary[f.entity_type] = summary.get(f.entity_type, 0) + 1
        return summary


# ── Text Masking ───────────────────────────────────────────────────────────────

def _mask_value(text: str, start: int, end: int) -> str:
    raw = text[start:end]
    if len(raw) <= 2:
        return "*" * len(raw)
    return raw[0] + "*" * (len(raw) - 2) + raw[-1]


# ── Text Chunking ──────────────────────────────────────────────────────────────

def chunk_text(text: str, chunk_size: int, overlap: int) -> List[tuple]:
    """Split text into overlapping chunks. Returns list of (text, offset) tuples."""
    chunks = []
    start = 0
    text_len = len(text)
    while start < text_len:
        end = min(start + chunk_size, text_len)
        chunks.append((text[start:end], start))
        if end == text_len:
            break
        start += chunk_size - overlap
    return chunks


# ══════════════════════════════════════════════════════════════════════════════
# NATIVE PATTERN ENGINE — Pure Python, no C extensions required
# ══════════════════════════════════════════════════════════════════════════════

class NativePatternMatcher:
    """
    Pure Python PII pattern matcher using only the `re` module.
    No spaCy, no Presidio, no C extensions — works on any Python version.
    
    Covers:
      - NPI (10-digit, Luhn validated)
      - Email addresses
      - US Phone numbers
      - US SSN
      - Credit/Debit cards (Luhn validated)
      - Korean RRN (주민등록번호, checksum validated)
      - Korean Passport (여권번호)
      - Korean Credit/Debit cards (Luhn validated)
      - Korean Phone numbers
    """

    # Each pattern: (entity_type, regex, base_score, validator_fn_or_None)
    PATTERNS: List[Tuple[str, str, float, Optional[callable]]] = [
        # NPI: 10-digit number, validated by Luhn
        ("NPI", r"\b\d{10}\b", 0.3, lambda m: validate_npi_luhn(m)),

        # Email
        ("EMAIL_ADDRESS",
         r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
         0.85, None),

        # US Phone
        ("PHONE_NUMBER",
         r"\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b",
         0.5, None),

        # US SSN
        ("US_SSN",
         r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b",
         0.65, None),

        # Credit/Debit card — 4-4-4-4 grouped format
        ("CREDIT_CARD",
         r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b",
         0.7, lambda m: validate_luhn(m)),

        # Credit/Debit card — continuous 13-19 digits starting with 3-6
        ("CREDIT_CARD",
         r"\b[3-6]\d{12,18}\b",
         0.4, lambda m: validate_luhn(m)),

        # Korean RRN with hyphen: YYMMDD-GNNNNNC
        ("KR_RRN",
         r"\b(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-\u2013]\s?[1-4]\d{6}\b",
         0.75, lambda m: validate_rrn_checksum("".join(c for c in m if c.isdigit()))),

        # Korean RRN without hyphen
        ("KR_RRN",
         r"\b(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[1-4]\d{6}\b",
         0.5, lambda m: validate_rrn_checksum(m)),

        # Korean Passport (old: 1 letter + 8 digits)
        ("KR_PASSPORT", r"\b[A-Z]\d{8}\b", 0.5, None),

        # Korean Passport (new: 2 letters + 7 digits)
        ("KR_PASSPORT", r"\b[A-Z]{2}\d{7}\b", 0.5, None),

        # Korean Card (4-4-4-4 with hyphens/spaces)
        ("KR_CARD_NUMBER",
         r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b",
         0.7, lambda m: validate_luhn(m)),

        # Korean Mobile: 010/011/016/017/018/019
        ("KR_PHONE",
         r"\b01[016789][-.\s]?\d{3,4}[-.\s]?\d{4}\b",
         0.7, None),

        # Korean Landline: 02/031/032/...
        ("KR_PHONE",
         r"\b0[2-6][1-5]?[-.\s]?\d{3,4}[-.\s]?\d{4}\b",
         0.6, None),

        # Korean phone with country code +82
        ("KR_PHONE",
         r"\+82[-.\s]?10[-.\s]?\d{4}[-.\s]?\d{4}\b",
         0.8, None),
    ]

    # Context keywords that boost score by +0.15 when nearby
    CONTEXT_BOOSTS: Dict[str, List[str]] = {
        "NPI": ["npi", "national provider", "provider identifier", "billing provider",
                "rendering provider", "medicare", "medicaid", "cms"],
        "KR_RRN": ["주민등록", "주민번호", "resident registration", "rrn"],
        "KR_PASSPORT": ["여권", "passport", "travel document"],
        "KR_CARD_NUMBER": ["카드번호", "신용카드", "체크카드", "card number"],
        "CREDIT_CARD": ["credit card", "debit card", "card number", "visa", "mastercard"],
        "KR_PHONE": ["전화번호", "연락처", "핸드폰", "휴대폰", "phone", "mobile"],
    }

    def __init__(self, confidence_threshold: float = 0.4):
        self.threshold = confidence_threshold
        # Pre-compile all patterns
        self._compiled = [
            (entity, re.compile(pattern, re.IGNORECASE), base_score, validator)
            for entity, pattern, base_score, validator in self.PATTERNS
        ]
        logger.info(f"🔧 Native pattern engine: {len(self._compiled)} patterns loaded")

    def _get_context(self, text: str, start: int, end: int, window: int = 50) -> str:
        """Extract surrounding context text for confidence boosting."""
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        return text[ctx_start:ctx_end].lower()

    def _apply_context_boost(self, entity: str, context: str) -> float:
        """Return confidence boost if context words present."""
        keywords = self.CONTEXT_BOOSTS.get(entity, [])
        for kw in keywords:
            if kw.lower() in context:
                return 0.15
        return 0.0

    def match(self, text: str) -> List[ScanFinding]:
        """
        Run all patterns against text, validate, and return findings.
        Deduplicates overlapping results.
        """
        raw_findings: List[ScanFinding] = []

        for entity, pattern, base_score, validator in self._compiled:
            for match in pattern.finditer(text):
                matched_text = match.group()
                start, end = match.start(), match.end()

                score = base_score

                # Apply validator (Luhn, RRN checksum, etc.)
                if validator:
                    try:
                        digits = "".join(c for c in matched_text if c.isdigit())
                        is_valid = validator(digits if digits else matched_text)
                        if is_valid is False:
                            continue  # Skip invalid
                        if is_valid is True:
                            score = min(0.95, score + 0.55)  # Boost validated matches
                    except Exception:
                        continue

                # Apply context boost
                context = self._get_context(text, start, end)
                score = min(0.98, score + self._apply_context_boost(entity, context))

                if score >= self.threshold:
                    raw_findings.append(ScanFinding(
                        entity_type=entity,
                        confidence=round(score, 4),
                        start=start,
                        end=end,
                        masked_value=_mask_value(text, start, end),
                    ))

        return self._deduplicate(raw_findings)

    def _deduplicate(self, findings: List[ScanFinding]) -> List[ScanFinding]:
        """Remove overlapping findings, keeping highest confidence."""
        if not findings:
            return []
        sorted_f = sorted(findings, key=lambda f: (f.start, -f.confidence))
        deduped = []
        for f in sorted_f:
            overlap = any(
                a.entity_type == f.entity_type
                and a.start <= f.end
                and f.start <= a.end
                for a in deduped
            )
            if not overlap:
                deduped.append(f)
        return deduped


# ══════════════════════════════════════════════════════════════════════════════
# PRESIDIO WRAPPER ENGINE — Uses Presidio + spaCy when available
# ══════════════════════════════════════════════════════════════════════════════

class PresidioEngine:
    """Presidio-backed engine that wraps AnalyzerEngine."""

    def __init__(self, scan_config: ScanConfig):
        self.config = scan_config
        self._analyzer = None

    def initialize(self) -> bool:
        """Try to initialize Presidio. Returns True on success."""
        try:
            from presidio_analyzer import AnalyzerEngine, RecognizerResult
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            from npi_recognizer import NPIRecognizer
            from korean_recognizer import get_korean_recognizers

            logger.info("   Loading spaCy model: en_core_web_lg...")
            nlp_config = {"nlp_engine_name": "spacy",
                         "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]}
            provider = NlpEngineProvider(nlp_configuration=nlp_config)
            nlp_engine = provider.create_engine()
            self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine,
                                           supported_languages=["en"])
            self._analyzer.registry.add_recognizer(NPIRecognizer())
            for r in get_korean_recognizers():
                self._analyzer.registry.add_recognizer(r)
            return True
        except Exception as e:
            logger.debug(f"Presidio init failed: {e}")
            return False

    def analyze(self, text: str, entities: List[str], threshold: float) -> List[ScanFinding]:
        from presidio_analyzer import RecognizerResult
        results = self._analyzer.analyze(
            text=text, language="en",
            entities=entities, score_threshold=threshold
        )
        return [
            ScanFinding(
                entity_type=r.entity_type,
                confidence=round(r.score, 4),
                start=r.start, end=r.end,
                masked_value=_mask_value(text, r.start, r.end),
            )
            for r in results
        ]


# ══════════════════════════════════════════════════════════════════════════════
# SCANNER ENGINE — Unified interface auto-selecting best available engine
# ══════════════════════════════════════════════════════════════════════════════

class ScannerEngine:
    """
    Main scanner with automatic engine selection:
      - Tries Presidio+spaCy first (full NER: PERSON, LOCATION + all entities)
      - Falls back to native Python patterns (NPI, Korean PII, cards, email, SSN)
    """

    def __init__(self, scan_config: ScanConfig):
        self.config = scan_config
        self._presidio: Optional[PresidioEngine] = None
        self._native: Optional[NativePatternMatcher] = None
        self._mode: str = "uninitialized"

    def initialize(self) -> None:
        logger.info("🔧 Initializing PII Scanner Engine...")

        # Try Presidio first
        presidio = PresidioEngine(self.config)
        if presidio.initialize():
            self._presidio = presidio
            self._mode = "presidio"
            logger.info("✅ Mode: PRESIDIO + spaCy en_core_web_lg (full NER)")
        else:
            # Fallback to native patterns
            self._native = NativePatternMatcher(
                confidence_threshold=self.config.confidence_threshold
            )
            self._mode = "native"
            logger.warning(
                "⚠️  Mode: NATIVE PATTERN MATCHING\n"
                "   spaCy/Presidio unavailable (requires Microsoft Visual C++ Redistributable).\n"
                "   Detects: NPI, Email, Phone, SSN, Credit Cards, Korean PII (RRN, Passport, Card, Phone)\n"
                "   Missing: PERSON names, LOCATION (requires spaCy NER)\n"
                "   Install VC++ Redistributable from: https://aka.ms/vs/17/release/vc_redist.x64.exe\n"
                "   Then reinstall: python -m pip install --force-reinstall spacy presidio-analyzer"
            )

        logger.info(f"   Engine ready — mode: {self._mode.upper()}")

    def _analyze_chunk(self, text: str, offset: int) -> List[ScanFinding]:
        """Analyze one chunk and adjust offsets back to original text coordinates."""
        if self._mode == "presidio":
            findings = self._presidio.analyze(
                text, self.config.entities, self.config.confidence_threshold
            )
        else:
            findings = self._native.match(text)

        # Adjust offsets for chunk position in original text
        for f in findings:
            f.start += offset
            f.end += offset

        return findings

    def _deduplicate(self, findings: List[ScanFinding]) -> List[ScanFinding]:
        """Remove cross-chunk duplicates keeping highest confidence."""
        if not findings:
            return []
        sorted_f = sorted(findings, key=lambda f: (f.start, -f.confidence))
        deduped = []
        for f in sorted_f:
            overlap = any(
                a.entity_type == f.entity_type
                and a.start <= f.end
                and f.start <= a.end
                for a in deduped
            )
            if not overlap:
                deduped.append(f)
        return deduped

    def scan_text(self, text: str, file_name: str) -> List[ScanFinding]:
        """
        Scan plain text for PII using chunked parallel analysis.
        Never logs raw PII values.
        """
        if not text or not text.strip():
            return []

        chunks = chunk_text(text, self.config.chunk_size, self.config.chunk_overlap)
        logger.info(
            f"  🔬 '{file_name}': {len(text):,} chars → "
            f"{len(chunks)} chunk(s) [{self._mode}]"
        )

        all_findings: List[ScanFinding] = []
        with ThreadPoolExecutor(
            max_workers=min(len(chunks), self.config.max_workers)
        ) as executor:
            futures = {
                executor.submit(self._analyze_chunk, ct, offset): i
                for i, (ct, offset) in enumerate(chunks)
            }
            for future in as_completed(futures):
                try:
                    all_findings.extend(future.result())
                except Exception as e:
                    logger.error(f"  Chunk error: {e}")

        deduped = self._deduplicate(all_findings)

        if deduped:
            summary = {}
            for f in deduped:
                summary[f.entity_type] = summary.get(f.entity_type, 0) + 1
            logger.info(
                f"  ⚠️  {len(deduped)} PII finding(s): "
                + ", ".join(f"{t}×{c}" for t, c in summary.items())
            )
        else:
            logger.info(f"  ✅ Clean: '{file_name}'")

        return deduped
