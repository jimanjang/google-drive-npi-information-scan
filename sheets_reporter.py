"""
sheets_reporter.py — Google Sheets Report Integration
======================================================
Writes scan results to a Google Spreadsheet for easy sharing
and dashboard visualization. Creates a new sheet if it doesn't exist,
or appends/overwrites rows on each scan run.

Sheet Layout:
  Tab 1 — "Summary"      : scan metadata and aggregate statistics
  Tab 2 — "Flagged Files": one row per flagged file with risk score
  Tab 3 — "All Findings" : one row per individual PII finding
"""

import logging
from datetime import datetime, timezone
from typing import List, Optional

import gspread
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from scanner_engine import FileScanResult

logger = logging.getLogger("scanner.sheets_reporter")

# Limit the number of individual findings to prevent Google Sheets from hanging
MAX_FINDINGS_PER_SHEET = 50000


# ── Column Headers ─────────────────────────────────────────────────────────────

SUMMARY_HEADERS = [
    "Scan Timestamp", "Scanner Version", "Folder ID",
    "Total Files", "Flagged Files", "Clean Files", "Error Files",
    "Total PII Findings", "Duration (s)",
    "CRITICAL", "HIGH", "MEDIUM", "LOW",
]

FLAGGED_HEADERS = [
    "File Name", "File Path", "File ID", "MIME Type",
    "Risk Level", "Risk Score", "Total Findings",
    "NPI", "PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS",
    "LOCATION", "CREDIT_CARD", "US_SSN",
    "KR_RRN", "KR_PASSPORT", "KR_CARD_NUMBER", "KR_PHONE",
    "Modified Time",
]


def _get_gspread_client(credentials_path: str, token_path: str) -> gspread.Client:
    """
    Create an authorized gspread client reusing existing OAuth credentials
    or Service Account credentials.
    """
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google.oauth2 import service_account
    import json
    import os

    scopes = [
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/spreadsheets",
    ]

    try:
        with open(credentials_path, 'r', encoding='utf-8') as f:
            cred_data = json.load(f)
    except Exception:
        cred_data = {}

    if cred_data.get("type") == "service_account":
        creds = service_account.Credentials.from_service_account_file(
            credentials_path, scopes=scopes
        )
    else:
        creds = Credentials.from_authorized_user_file(token_path, scopes)
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())

    return gspread.authorize(creds)


def _get_or_create_worksheet(
    spreadsheet: gspread.Spreadsheet, title: str, headers: List[str]
) -> gspread.Worksheet:
    """
    Get an existing worksheet by title or create one with the given headers.
    Clears existing content before writing new scan data.
    """
    try:
        ws = spreadsheet.worksheet(title)
        ws.clear()
        logger.debug(f"  Cleared existing sheet: '{title}'")
    except gspread.exceptions.WorksheetNotFound:
        ws = spreadsheet.add_worksheet(title=title, rows=5000, cols=30)
        logger.info(f"  Created new sheet: '{title}'")

    # Write header row (bold via user format)
    ws.append_row(headers)
    return ws


def write_to_sheets(
    results: List[FileScanResult],
    spreadsheet_id: str,
    sheet_name: str,
    credentials_path: str,
    token_path: str,
    scan_folder_id: str,
    duration_seconds: float,
) -> Optional[str]:
    """
    Write complete scan results to Google Sheets.

    Creates three tabs:
      - Summary: top-level scan statistics
      - Flagged Files: per-file risk scores and entity counts
      - All Findings: every individual PII finding (masked)

    Args:
        results:          All FileScanResult objects from the scan.
        spreadsheet_id:   Google Sheets document ID (from URL).
        sheet_name:       Display name prefix for sheet tabs.
        credentials_path: Path to OAuth client_secret.json.
        token_path:       Path to cached OAuth token.json.
        scan_folder_id:   Drive folder that was scanned.
        duration_seconds: Scan duration for the summary.

    Returns:
        URL of the Google Spreadsheet on success, None on failure.
    """
    if not spreadsheet_id:
        logger.info("ℹ️  No REPORT_SPREADSHEET_ID configured — skipping Sheets upload")
        return None

    try:
        logger.info(f"📊 Writing report to Google Sheets (id: {spreadsheet_id})")
        client = _get_gspread_client(credentials_path, token_path)
        spreadsheet = client.open_by_key(spreadsheet_id)

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        flagged = [r for r in results if r.findings and not r.error]
        clean   = [r for r in results if not r.findings and not r.error]
        errors  = [r for r in results if r.error]

        # ── Tab 1: Summary ─────────────────────────────────────────────────────
        summary_ws = _get_or_create_worksheet(
            spreadsheet, f"{sheet_name} — Summary", SUMMARY_HEADERS
        )

        risk_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in flagged:
            risk_dist[r.risk_level] = risk_dist.get(r.risk_level, 0) + 1

        summary_ws.append_row([
            now_str,
            "1.0.0",
            scan_folder_id,
            len(results),
            len(flagged),
            len(clean),
            len(errors),
            sum(len(r.findings) for r in flagged),
            round(duration_seconds, 2),
            risk_dist["CRITICAL"],
            risk_dist["HIGH"],
            risk_dist["MEDIUM"],
            risk_dist["LOW"],
        ])
        logger.info("  ✅ Summary tab written")

        # ── Tab 2: Flagged Files ───────────────────────────────────────────────
        flagged_ws = _get_or_create_worksheet(
            spreadsheet, f"{sheet_name} — Flagged Files", FLAGGED_HEADERS
        )

        flagged_sorted = sorted(flagged, key=lambda r: r.risk_score, reverse=True)
        flagged_rows = []
        for result in flagged_sorted:
            es = result.entity_summary
            flagged_rows.append([
                result.file_name,
                result.file_path,
                result.file_id,
                result.mime_type,
                result.risk_level,
                round(result.risk_score, 4),
                len(result.findings),
                es.get("NPI", 0),
                es.get("PERSON", 0),
                es.get("PHONE_NUMBER", 0),
                es.get("EMAIL_ADDRESS", 0),
                es.get("LOCATION", 0),
                es.get("CREDIT_CARD", 0),
                es.get("US_SSN", 0),
                es.get("KR_RRN", 0),
                es.get("KR_PASSPORT", 0),
                es.get("KR_CARD_NUMBER", 0),
                es.get("KR_PHONE", 0),
                result.modified_time,
            ])
        if flagged_rows:
            flagged_ws.append_rows(flagged_rows)
        logger.info(f"  ✅ Flagged Files tab: {len(flagged_rows)} row(s)")

        # Apply conditional formatting colors by risk level (best-effort)
        try:
            _apply_risk_formatting(spreadsheet, flagged_ws)
        except Exception as e:
            logger.debug(f"  Conditional formatting skipped: {e}")

        url = f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}"
        logger.info(f"  🔗 Sheets report: {url}")
        return url

    except gspread.exceptions.APIError as e:
        logger.error(f"❌ Google Sheets API error: {e}")
        return None
    except Exception as e:
        logger.error(f"❌ Sheets upload failed: {e}")
        return None


def _apply_risk_formatting(
    spreadsheet: gspread.Spreadsheet,
    worksheet: gspread.Worksheet,
) -> None:
    """
    Apply background color formatting to Risk Level column using Conditional Formatting Rules.
    This is MUCH faster than per-cell formatting for large datasets.
    """
    # Risk Color Map (RGB 0-1)
    risk_colors = {
        "CRITICAL": {"red": 0.96, "green": 0.26, "blue": 0.21},
        "HIGH":     {"red": 1.0,  "green": 0.60, "blue": 0.0},
        "MEDIUM":   {"red": 1.0,  "green": 0.92, "blue": 0.23},
        "LOW":      {"red": 0.30, "green": 0.69, "blue": 0.31},
    }

    # Identify the column index for "Risk Level" (column 4 for FLAGGED_HEADERS, column 7 for FINDINGS_HEADERS)
    # We'll apply it to the specific worksheet based on its current headers if possible, 
    # but for simplicity let's assume standard headers.
    
    requests = []
    
    # Define rules for each risk level
    for risk_level, color in risk_colors.items():
        requests.append({
            "addConditionalFormatRule": {
                "rule": {
                    "ranges": [{
                        "sheetId": worksheet.id,
                        "startRowIndex": 1, # Skip header
                    }],
                    "booleanRule": {
                        "condition": {
                            "type": "TEXT_EQ",
                            "values": [{"userEnteredValue": risk_level}]
                        },
                        "format": {
                            "backgroundColor": color,
                            "textFormat": {"bold": True}
                        }
                    }
                },
                "index": 0
            }
        })
    
    if requests:
        spreadsheet.batch_update({"requests": requests})
        logger.info(f"  ✅ Applied conditional formatting rules to '{worksheet.title}'")
