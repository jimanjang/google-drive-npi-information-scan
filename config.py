"""
config.py — Central Configuration for AI-Powered Security Scanner
=================================================================
Loads environment variables, defines dataclass-based settings,
and provides validated configuration for all scanner modules.
"""

import os
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv

# ── Load .env ──────────────────────────────────────────────────────────────────
load_dotenv()

# ── Logging Setup ──────────────────────────────────────────────────────────────
LOG_FORMAT = "%(asctime)s │ %(levelname)-8s │ %(name)-20s │ %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, datefmt=DATE_FORMAT)
logger = logging.getLogger("scanner.config")


# ── Supported MIME Types ───────────────────────────────────────────────────────
MIME_TYPE_MAP = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "text/plain": ".txt",
    # Google native formats → export conversions
    "application/vnd.google-apps.document": "text/plain",        # Google Docs → TXT
    "application/vnd.google-apps.spreadsheet": "text/csv",       # Google Sheets → CSV
}

GOOGLE_NATIVE_TYPES = {
    "application/vnd.google-apps.document",
    "application/vnd.google-apps.spreadsheet",
}

SCANNABLE_MIME_TYPES = list(MIME_TYPE_MAP.keys())


# ── Target Entities ────────────────────────────────────────────────────────────
DEFAULT_ENTITIES = [
    "NPI",
    "PERSON",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "LOCATION",
    "CREDIT_CARD",
    "US_SSN",
    "KR_RRN",           # Korean Resident Registration Number (주민등록번호)
    "KR_PASSPORT",      # Korean Passport Number (여권번호)
    "KR_CARD_NUMBER",   # Korean Credit/Debit Card Number
    "KR_PHONE",         # Korean Phone Number
]


@dataclass
class GoogleAuthConfig:
    """Google OAuth 2.0 authentication settings."""
    oauth_credentials_path: str = os.getenv(
        "GOOGLE_OAUTH_CREDENTIALS_PATH", "credentials/client_secret.json"
    )
    token_path: str = os.getenv(
        "GOOGLE_TOKEN_PATH", "credentials/token.json"
    )
    impersonate_user_email: Optional[str] = os.getenv(
        "IMPERSONATE_USER_EMAIL", None
    )
    scopes: List[str] = field(default_factory=lambda: [
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/spreadsheets",
    ])


@dataclass
class ScanConfig:
    """Scan scope and processing settings."""
    folder_id: str = os.getenv("SCAN_FOLDER_ID", "root")
    max_workers: int = int(os.getenv("MAX_WORKERS", "4"))
    chunk_size: int = int(os.getenv("CHUNK_SIZE", "10000"))
    chunk_overlap: int = int(os.getenv("CHUNK_OVERLAP", "200"))
    mime_types: List[str] = field(default_factory=lambda: SCANNABLE_MIME_TYPES)
    entities: List[str] = field(default_factory=lambda: DEFAULT_ENTITIES)
    confidence_threshold: float = 0.4  # Minimum confidence to report


@dataclass
class RateLimitConfig:
    """Rate limiting settings for API calls."""
    requests_per_second: float = float(os.getenv("RATE_LIMIT_RPS", "10"))
    burst_size: int = 15  # Allow short bursts


@dataclass
class OutputConfig:
    """Output and reporting settings."""
    output_dir: str = os.getenv("OUTPUT_DIR", "reports")
    spreadsheet_id: Optional[str] = os.getenv("REPORT_SPREADSHEET_ID", None)
    sheet_name: str = os.getenv("REPORT_SHEET_NAME", "Security Scan Report")


@dataclass
class ScannerConfig:
    """Root configuration aggregating all sub-configs."""
    auth: GoogleAuthConfig = field(default_factory=GoogleAuthConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    output: OutputConfig = field(default_factory=OutputConfig)

    def validate(self) -> bool:
        """Validate critical configuration paths and values."""
        creds_path = Path(self.auth.oauth_credentials_path)
        if not creds_path.exists():
            logger.warning(
                f"OAuth credentials not found at '{creds_path}'. "
                "Please download from Google Cloud Console → APIs & Services → Credentials."
            )
            return False

        # Ensure output directory exists
        Path(self.output.output_dir).mkdir(parents=True, exist_ok=True)

        logger.info("✅ Configuration validated successfully.")
        return True


def load_config() -> ScannerConfig:
    """Factory function to create and return validated configuration."""
    config = ScannerConfig()
    logger.info(f"📂 Scan target: folder_id='{config.scan.folder_id}'")
    logger.info(f"⚡ Workers: {config.scan.max_workers} | Chunk: {config.scan.chunk_size} chars")
    logger.info(f"🔒 Rate limit: {config.rate_limit.requests_per_second} req/s")
    return config
