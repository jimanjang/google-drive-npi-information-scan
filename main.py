"""
main.py — AI-Powered Security Scanner CLI Entry Point
======================================================
Orchestrates the complete scan pipeline:
  1. Load configuration
  2. Authenticate with Google Drive (OAuth 2.0)
  3. List scannable files (recursive)
  4. Extract text from each file
  5. Scan with Presidio (NPI + PII + Korean PII)
  6. Generate JSON report
  7. (Optional) Upload to Google Sheets

Usage:
  python main.py                        # Scan 'root' with .env config
  python main.py --folder-id FOLDER_ID  # Scan specific folder
  python main.py --local-test           # Test with local sample files
  python main.py --help                 # Show all options
"""

import argparse
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional

from tqdm import tqdm

from config import load_config, ScannerConfig
from drive_client import DriveClient, DriveFile
from file_extractor import extract_text
from rate_limiter import RateLimiter
from scanner_engine import ScannerEngine, FileScanResult
from report_generator import save_json_report, print_console_summary
from sheets_reporter import write_to_sheets

logger = logging.getLogger("scanner.main")

BASE_DIR = Path(__file__).parent.absolute()
LOCK_FILE = str(BASE_DIR / ".scan_lock")

def update_lock_status(status: str, detail: str = ""):
    """Update the lock file with a status suffix like PID:STATUS:DETAIL"""
    try:
        pid = os.getpid()
        with open(LOCK_FILE, "w") as f:
            f.write(f"{pid}:{status}:{detail}")
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# Local Test Mode — Scan files on disk without Google Drive
# ══════════════════════════════════════════════════════════════════════════════

def run_local_test(engine: ScannerEngine, config: ScannerConfig) -> List[FileScanResult]:
    """
    Scan local files in the 'test_samples/' directory.
    Creates sample files with mock PII if none exist.
    """
    samples_dir = Path("test_samples")
    samples_dir.mkdir(exist_ok=True)

    # Create sample files if not present
    _create_sample_files(samples_dir)

    results = []
    sample_files = list(samples_dir.glob("*"))

    logger.info(f"Local test mode: scanning {len(sample_files)} file(s) in '{samples_dir}/'")

    for filepath in sample_files:
        try:
            with open(filepath, "rb") as f:
                file_bytes = f.read()

            # Determine MIME type from extension
            ext_map = {".txt": "text/plain", ".pdf": "application/pdf",
                       ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
            mime = ext_map.get(filepath.suffix.lower(), "text/plain")

            text = extract_text(file_bytes, mime)
            if text is None:
                text = file_bytes.decode("utf-8", errors="replace")

            findings = engine.scan_text(text, filepath.name)

            results.append(FileScanResult(
                file_id=f"local_{filepath.stem}",
                file_name=filepath.name,
                file_path=str(filepath),
                owner="local-system",
                mime_type=mime,
                modified_time="",
                total_chars=len(text),
                findings=findings,
            ))

        except Exception as e:
            logger.error(f"Error: Local test error for '{filepath.name}': {e}")
            results.append(FileScanResult(
                file_id=f"local_{filepath.stem}",
                file_name=filepath.name,
                file_path=str(filepath),
                owner="local-system",
                mime_type="text/plain",
                modified_time="",
                error=str(e),
            ))

    return results


def _create_sample_files(samples_dir: Path) -> None:
    """Create sample test files with mock PII data if they don't exist."""
    # Sample 1: Healthcare record with NPI and SSN (English)
    sample_en = samples_dir / "sample_healthcare_en.txt"
    if not sample_en.exists():
        sample_en.write_text(
            "Patient Record — Confidential\n"
            "Patient: John Smith\n"
            "Email: john.smith@hospital.org\n"
            "Phone: 555-867-5309\n"
            "SSN: 123-45-6789\n"
            "Billing Provider NPI: 1234567893\n"  # Valid NPI with correct Luhn
            "Location: 123 Main Street, New York, NY 10001\n"
            "Credit Card: 4532015112830366\n",   # Valid Visa (Luhn-valid)
            encoding="utf-8",
        )
        logger.info("  Created: sample_healthcare_en.txt")

    # Sample 2: Korean PII record
    sample_kr = samples_dir / "sample_korean_pii.txt"
    if not sample_kr.exists():
        sample_kr.write_text(
            "개인정보 처리방침 테스트\n"
            "이름: 홍길동\n"
            "주민등록번호: 900101-1234567\n"
            "연락처: 010-1234-5678\n"
            "여권번호: M12345678\n"
            "신용카드: 9410-0523-6120-0902\n"
            "이메일: hong@example.kr\n",
            encoding="utf-8",
        )
        logger.info("  Created: sample_korean_pii.txt")

    # Sample 3: Clean file (no PII)
    sample_clean = samples_dir / "sample_clean_document.txt"
    if not sample_clean.exists():
        sample_clean.write_text(
            "Annual Report — FY2024\n"
            "Revenue: $4.2M\n"
            "Operating margin: 18.3%\n"
            "Headcount: 142 employees\n"
            "This document contains no personal information.\n",
            encoding="utf-8",
        )
        logger.info("  Created: sample_clean_document.txt")


# ══════════════════════════════════════════════════════════════════════════════
# Process a single file: download → extract → scan
# ══════════════════════════════════════════════════════════════════════════════

def process_file(
    drive_file: DriveFile,
    drive_client: DriveClient,
    engine: ScannerEngine,
) -> FileScanResult:
    """
    Complete file processing pipeline: download → extract text → scan.
    Errors are caught per-file so that one failure doesn't stop the batch.
    """
    result = FileScanResult(
        file_id=drive_file.file_id,
        file_name=drive_file.name,
        file_path=drive_file.path,
        owner=drive_file.owner,
        mime_type=drive_file.mime_type,
        modified_time=drive_file.modified_time,
    )

    try:
        # Step 1: Download binary content
        file_bytes = drive_client.download_file(drive_file)
        if file_bytes is None:
            result.error = "Download failed (permission denied or not found)"
            return result

        # Step 2: Extract text
        text = extract_text(file_bytes, drive_file.mime_type)
        if text is None or not text.strip():
            result.error = "Text extraction returned empty content"
            return result

        result.total_chars = len(text)

        # Step 3: Scan for PII
        result.findings = engine.scan_text(text, drive_file.name)

    except MemoryError:
        result.error = "File too large for available memory"
        logger.error(f"Memory error processing '{drive_file.name}' ({drive_file.size:,} bytes)")

    except Exception as e:
        result.error = str(e)
        logger.error(f"Error: Unexpected error for '{drive_file.name}': {e}")

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Main Orchestrator
# ══════════════════════════════════════════════════════════════════════════════

def run_scan(args: argparse.Namespace) -> int:
    """
    Main scan orchestration function.
    Returns exit code: 0 = success, 1 = error, 2 = PII found.
    """
    start_time = time.time()

    # ── 1. Load Config ────────────────────────────────────────────────────────
    config = load_config()

    # Apply CLI overrides
    if args.folder_id:
        config.scan.folder_id = args.folder_id
    if args.workers:
        config.scan.max_workers = args.workers
    if args.output_dir:
        config.output.output_dir = args.output_dir
    if args.spreadsheet_id:
        config.output.spreadsheet_id = args.spreadsheet_id

    # ── 2. Initialize Scanner Engine ──────────────────────────────────────────
    engine = ScannerEngine(config.scan)
    try:
        engine.initialize()
    except Exception as e:
        logger.error(f"Error: Engine initialization failed: {e}")
        return 1

    # ── 3. Local Test Mode ────────────────────────────────────────────────────
    if args.local_test:
        logger.info("Running in LOCAL TEST mode (no Google Drive connection)")
        results = run_local_test(engine, config)
        duration = time.time() - start_time

        print_console_summary(results)
        report_path = save_json_report(
            results, config.output.output_dir, "local-test", duration
        )

        if config.output.spreadsheet_id:
            write_to_sheets(
                results=results,
                spreadsheet_id=config.output.spreadsheet_id,
                sheet_name=config.output.sheet_name,
                credentials_path=config.auth.oauth_credentials_path,
                token_path=config.auth.token_path,
                scan_folder_id="local-test",
                duration_seconds=duration,
            )

        flagged_count = sum(1 for r in results if r.findings)
        return 2 if flagged_count > 0 else 0

    # ── 4. Google Drive Authentication ────────────────────────────────────────
    rate_limiter = RateLimiter(
        rate=config.rate_limit.requests_per_second,
        burst=config.rate_limit.burst_size,
    )

    drive_client = DriveClient(config.auth, rate_limiter)
    if not drive_client.authenticate():
        logger.error(
            "Error: Authentication failed.\n"
            "   Please ensure credentials/client_secret.json exists.\n"
            "   See README.md for setup instructions."
        )
        return 1

    # ── 5. List Files ─────────────────────────────────────────────────────────
    drive_files: List[DriveFile] = []
    try:
        if config.scan.scan_all_users:
            logger.info("SCAN_ALL_USERS is enabled. Discovering files across all domain users...")
            users = drive_client.list_all_users()
            if not users:
                logger.warning("Directory API returned no users or failed. Falling back to primary user scan.")
                if config.auth.impersonate_user_email:
                    users = [config.auth.impersonate_user_email]
                else:
                    # If everything else fails, we'll hit the 'if not drive_files' check below
                    users = []
            
            total_users = len(users)
            for idx, user_email in enumerate(users, 1):
                update_lock_status("INDEXING", f"User ({idx}/{total_users}): {user_email}")
                # Switch impersonation target
                if drive_client.authenticate(impersonate_email=user_email):
                    try:
                        user_files = drive_client.list_files(config.scan, lambda d: update_lock_status("INDEXING", d))
                        drive_files.extend(user_files)
                    except Exception as ue:
                        logger.error(f"Failed to list files for {user_email}: {ue}")
                else:
                    logger.error(f"Error: Failed to impersonate {user_email}")
            
            # Deduplicate by file_id (files might be shared across users)
            seen_ids = set()
            unique_files = []
            for f in drive_files:
                if f.file_id not in seen_ids:
                    unique_files.append(f)
                    seen_ids.add(f.file_id)
            drive_files = unique_files
            logger.info(f"Total unique files discovered across domain: {len(drive_files)}")
        else:
            update_lock_status("INDEXING", "Discovering files in Drive...")
            drive_files = drive_client.list_files(config.scan, lambda d: update_lock_status("INDEXING", d))
    except Exception as e:
        logger.error(f"Error: Failed to list Drive files: {e}")
        return 1

    if not drive_files:
        logger.info("Info: No scannable files found. Check folder ID and file types.")
        return 0

    # ── 6. Process Files (Parallel) ───────────────────────────────────────────
    CACHE_FILE = str(BASE_DIR / "scan_cache.json")
    scan_cache = {}
    if Path(CACHE_FILE).exists():
        import json
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as cf:
                scan_cache = json.load(cf)
        except Exception as ce:
            logger.warning(f"Failed to read cache file: {ce}")

    results: List[FileScanResult] = []
    files_to_scan = []

    from scanner_engine import ScanFinding
    for f in drive_files:
        cached = scan_cache.get(f.file_id)
        if cached and cached.get("modified_time") == f.modified_time:
            findings = [ScanFinding(**fi) for fi in cached.get("findings", [])]
            results.append(FileScanResult(
                file_id=f.file_id,
                file_name=f.name,
                file_path=f.path,
                owner=f.owner,
                mime_type=f.mime_type,
                modified_time=f.modified_time,
                total_chars=cached.get("total_chars", 0),
                findings=findings,
                error=cached.get("error")
            ))
        else:
            files_to_scan.append(f)

    logger.info(f"\nStarting parallel scan of {len(files_to_scan)} file(s) (Skipped {len(drive_files) - len(files_to_scan)} cached)...")
    logger.info(f"   Workers: {config.scan.max_workers}")

    import json
    from dataclasses import asdict
    with ThreadPoolExecutor(max_workers=config.scan.max_workers) as executor:
        future_map = {
            executor.submit(process_file, f, drive_client, engine): f
            for f in files_to_scan
        }

        skip_count = len(drive_files) - len(files_to_scan)
        with tqdm(total=len(drive_files), initial=skip_count, unit="file", desc="Scanning") as pbar:
            for i, future in enumerate(as_completed(future_map), 1):
                drive_file = future_map[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Update cache sequentially on the main thread
                    scan_cache[result.file_id] = {
                        "modified_time": result.modified_time,
                        "total_chars": result.total_chars,
                        "findings": [asdict(fi) for fi in result.findings],
                        "error": result.error
                    }
                    
                    # Periodic UI status update
                    if (i + skip_count) % 10 == 0 or i == len(files_to_scan):
                        update_lock_status("SCANNING", f"{i + skip_count}/{len(drive_files)}")

                    # Checkpoint cache to disk
                    with open(CACHE_FILE, "w", encoding="utf-8") as cf:
                        json.dump(scan_cache, cf, ensure_ascii=False)
                        
                except Exception as e:
                    logger.error(f"Error: Unhandled error for '{drive_file.name}': {e}")
                    results.append(FileScanResult(
                        file_id=drive_file.file_id,
                        file_name=drive_file.name,
                        file_path=drive_file.path,
                        owner=drive_file.owner,
                        mime_type=drive_file.mime_type,
                        modified_time=drive_file.modified_time,
                        error=str(e),
                    ))
                finally:
                    pbar.update(1)

    duration = time.time() - start_time

    # ── 7. Reports ────────────────────────────────────────────────────────────
    print_console_summary(results)

    report_path = save_json_report(
        results, config.output.output_dir, config.scan.folder_id, duration
    )

    # Optional: Google Sheets upload
    if config.output.spreadsheet_id:
        update_lock_status("SYNCING")
        write_to_sheets(
            results=results,
            spreadsheet_id=config.output.spreadsheet_id,
            sheet_name=config.output.sheet_name,
            credentials_path=config.auth.oauth_credentials_path,
            token_path=config.auth.token_path,
            scan_folder_id=config.scan.folder_id,
            duration_seconds=duration,
        )

    # Rate limiter diagnostics
    stats = rate_limiter.get_stats()
    logger.info(
        f"📡 API stats: {stats['total_requests']} requests, "
        f"avg wait {stats['avg_wait_ms']}ms"
    )

    flagged_count = sum(1 for r in results if r.findings)
    return 2 if flagged_count > 0 else 0


# ══════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-scanner",
        description=(
            "🔒 AI-Powered Security Scanner\n"
            "Scans Google Drive for NPI, PII (US + Korean) using Microsoft Presidio.\n"
            "\nExit codes: 0=clean, 1=error, 2=PII found"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--folder-id", "-f",
        default=None,
        help="Google Drive folder ID to scan (default: 'root' from .env)",
    )
    parser.add_argument(
        "--local-test", "-t",
        action="store_true",
        help="Run without Google Drive using local test_samples/ files",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=None,
        help="Number of parallel workers (default: 4 from .env)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=None,
        help="Directory for JSON report output (default: 'reports/' from .env)",
    )
    parser.add_argument(
        "--spreadsheet-id", "-s",
        default=None,
        help="Google Sheets ID for report upload (overrides .env)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG level logging",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print("\n" + "=" * 60)
    print("  [SECURE] AI-Powered Security Scanner")
    print("     Presidio + Google Drive + Korean PII")
    print("=" * 60 + "\n")

    # Create lock file to signal "is_running" to the dashboard
    lock_file_path = LOCK_FILE
    try:
        with open(lock_file_path, "w") as f:
            f.write(f"{os.getpid()}:INDEXING:Initializing...")
        
        exit_code = run_scan(args)
    finally:
        if os.path.exists(lock_file_path):
            os.remove(lock_file_path)

    if exit_code == 2:
        print("\n[!] SCAN COMPLETE - PII DETECTED. Review the report.\n")
    elif exit_code == 0:
        print("\n[OK] SCAN COMPLETE - No PII found.\n")
    else:
        print("\n[ERROR] SCAN FAILED. Check logs for details.\n")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
