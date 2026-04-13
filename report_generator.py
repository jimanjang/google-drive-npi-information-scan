"""
report_generator.py — JSON Scan Report Generator
=================================================
Aggregates FileScanResult objects into a structured JSON report.
All raw PII values are MASKED — only entity types, positions, and
masked representations are stored. Never logs sensitive information.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from scanner_engine import FileScanResult

logger = logging.getLogger("scanner.report_generator")


# ── Risk Score → Category Mapping (for human-readable reports) ──────────────────
RISK_COLORS = {
    "CRITICAL": "!!!",
    "HIGH":     "!! ",
    "MEDIUM":   "!  ",
    "LOW":      ".  ",
    "CLEAN":    "OK ",
}


def _build_report(
    results: List[FileScanResult],
    scan_folder_id: str,
    duration_seconds: float,
) -> dict:
    """
    Build the complete structured report dictionary.
    
    Structure:
      - metadata: scan info, timestamps, statistics
      - summary: aggregated counts and entity breakdown
      - flagged_files: files with PII findings (sorted by risk score)
      - clean_files: files with no findings (file names only)
      - errors: files that failed during processing
    """
    now = datetime.now(timezone.utc)

    # Split results by category
    flagged = [r for r in results if r.findings and not r.error]
    clean = [r for r in results if not r.findings and not r.error]
    errors = [r for r in results if r.error]

    # Aggregate entity type counts across all findings
    entity_totals: dict = {}
    for result in flagged:
        for entity_type, count in result.entity_summary.items():
            entity_totals[entity_type] = entity_totals.get(entity_type, 0) + count

    # Build flagged file entries (sorted: highest risk first)
    flagged_sorted = sorted(flagged, key=lambda r: r.risk_score, reverse=True)
    flagged_entries = []
    for result in flagged_sorted:
        entry = {
            "file_id": result.file_id,
            "file_name": result.file_name,
            "file_path": result.file_path,
            "mime_type": result.mime_type,
            "modified_time": result.modified_time,
            "risk_level": result.risk_level,
            "risk_score": round(result.risk_score, 4),
            "total_findings": len(result.findings),
            "entity_breakdown": result.entity_summary,
            "findings": [
                {
                    "entity_type": f.entity_type,
                    "confidence": f.confidence,
                    "masked_value": f.masked_value,
                    "start_index": f.start,
                    "end_index": f.end,
                }
                for f in sorted(result.findings, key=lambda x: x.start)
            ],
        }
        flagged_entries.append(entry)

    report = {
        "metadata": {
            "report_generated_at": now.isoformat(),
            "scan_folder_id": scan_folder_id,
            "scanner_version": "1.0.0",
            "scanner": "AI-Powered Security Scanner (Presidio + Google Drive)",
            "duration_seconds": round(duration_seconds, 2),
            "note": "All PII values are masked. Raw sensitive data is never stored.",
        },
        "summary": {
            "total_files_scanned": len(results),
            "flagged_files": len(flagged),
            "clean_files": len(clean),
            "error_files": len(errors),
            "total_pii_findings": sum(len(r.findings) for r in flagged),
            "entity_type_totals": dict(
                sorted(entity_totals.items(), key=lambda x: x[1], reverse=True)
            ),
            "risk_distribution": {
                "CRITICAL": sum(1 for r in flagged if r.risk_level == "CRITICAL"),
                "HIGH":     sum(1 for r in flagged if r.risk_level == "HIGH"),
                "MEDIUM":   sum(1 for r in flagged if r.risk_level == "MEDIUM"),
                "LOW":      sum(1 for r in flagged if r.risk_level == "LOW"),
            },
        },
        "flagged_files": flagged_entries,
        "clean_files": [
            {"file_id": r.file_id, "file_name": r.file_name, "file_path": r.file_path}
            for r in clean
        ],
        "errors": [
            {
                "file_id": r.file_id,
                "file_name": r.file_name,
                "file_path": r.file_path,
                "error": r.error,
            }
            for r in errors
        ],
    }

    return report


def save_json_report(
    results: List[FileScanResult],
    output_dir: str,
    scan_folder_id: str,
    duration_seconds: float,
) -> str:
    """
    Save the scan report as a timestamped JSON file.

    Args:
        results:          List of FileScanResult from all scanned files.
        output_dir:       Directory path for the report file.
        scan_folder_id:   Drive folder ID that was scanned.
        duration_seconds: Total scan duration for metadata.

    Returns:
        Absolute path to the saved report file.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    report = _build_report(results, scan_folder_id, duration_seconds)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
        
    # Also save a complete .txt log sequence for human readability
    txt_filename = f"scan_report_{timestamp}.txt"
    txt_filepath = os.path.join(output_dir, txt_filename)
    with open(txt_filepath, "w", encoding="utf-8") as tf:
        tf.write("AI-Powered Security Scanner - Full PII Findings Log\n")
        tf.write("=" * 60 + "\n\n")
        for file_entry in report["flagged_files"]:
            tf.write(f"[{file_entry['risk_level']}] File: {file_entry['file_name']} (ID: {file_entry['file_id']})\n")
            tf.write(f"Path: {file_entry['file_path']}\n")
            for finding in file_entry["findings"]:
                pos = f"{finding['start_index']}-{finding['end_index']}"
                tf.write(f"  - {finding['entity_type']:<15} : {finding['masked_value']:<30} (Pos: {pos})\n")
            tf.write("\n")

    # Log summary (no PII data in logs)
    summary = report["summary"]
    flagged_count = summary["flagged_files"]
    total_count = summary["total_files_scanned"]

    logger.info("=" * 60)
    logger.info("SCAN COMPLETE - REPORT SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Total files scanned : {total_count}")
    logger.info(f"  Flagged (PII found) : {flagged_count}")
    logger.info(f"  Clean files         : {summary['clean_files']}")
    logger.info(f"  Errors              : {summary['error_files']}")
    logger.info(f"  Total PII findings  : {summary['total_pii_findings']}")
    logger.info(f"  Duration            : {duration_seconds:.1f}s")

    if summary["entity_type_totals"]:
        logger.info("  Entity breakdown:")
        for entity, count in summary["entity_type_totals"].items():
            logger.info(f"    {entity:<25} {count:>4}")

    if flagged_count > 0:
        logger.info(f"  Risk distribution:")
        for level, count in summary["risk_distribution"].items():
            if count > 0:
                icon = RISK_COLORS.get(level, "")
                logger.info(f"    {icon} {level}: {count} file(s)")

    logger.info(f"  Report saved: {filepath}")
    logger.info("=" * 60)

    return filepath


def _safe_console_str(s: str) -> str:
    """Sanitize a string for Windows console (cp949) by replacing unencodable characters."""
    if not s:
        return ""
    try:
        # Try encoding to the current terminal encoding, replace bad chars with '?'
        encoding = sys.stdout.encoding or 'utf-8'
        return s.encode(encoding, errors='replace').decode(encoding)
    except Exception:
        # Fallback to pure ASCII/Replacement if everything fails
        return s.encode('ascii', errors='replace').decode('ascii')


def print_console_summary(results: List[FileScanResult]) -> None:
    """Print a quick human-readable summary to stdout."""
    flagged = [r for r in results if r.findings]
    if not flagged:
        print("\n[OK] No PII found in any scanned files.\n")
        return

    print(f"\n{'='*60}")
    print(f"PII DETECTED IN {len(flagged)} FILE(S)")
    print(f"{'='*60}")
    for result in sorted(flagged, key=lambda r: r.risk_score, reverse=True):
        icon = RISK_COLORS.get(result.risk_level, "")
        safe_name = _safe_console_str(result.file_name)
        safe_path = _safe_console_str(result.file_path)
        
        print(f"\n{icon} [{result.risk_level}] {safe_name}")
        print(f"   Path:     {safe_path}")
        print(f"   Score:    {result.risk_score:.2f}")
        print(f"   Findings: {len(result.findings)}")
        for entity_type, count in result.entity_summary.items():
            print(f"             - {entity_type}: {count}")
    print()
