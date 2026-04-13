import sqlite3
import json
import sys
import argparse
from pathlib import Path

# Paths
TARGET_DIR = Path(r"C:\Users\user\.antigravity\google drive scan for microsoft presidio")
DB_FILE = TARGET_DIR / "scan_cache.db"

def get_stats():
    if not DB_FILE.exists():
        return {"scannedCount": 0, "lastActivity": None}
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT count(*) FROM scan_results")
    scanned_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT max(last_scanned) FROM scan_results")
    last_activity = cursor.fetchone()[0]
    
    cursor.execute("SELECT count(*) FROM findings")
    findings_count = cursor.fetchone()[0]
    
    conn.close()
    return {
        "scannedCount": scanned_count,
        "findingsCount": findings_count,
        "lastActivity": last_activity
    }

def get_results():
    if not DB_FILE.exists():
        return {"scan_summary": {}, "flagged_files": []}
    
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all files with findings across the entire database
    cursor.execute("""
        SELECT s.file_id, s.modified_time, s.total_chars, s.error
        FROM scan_results s
        WHERE EXISTS (SELECT 1 FROM findings f WHERE f.file_id = s.file_id)
    """)
    files = cursor.fetchall()
    
    flagged_files = []
    total_findings = 0
    risk_CRITICAL = 0
    risk_HIGH = 0
    
    for f in files:
        file_id = f["file_id"]
        cursor.execute("SELECT entity_type, confidence, masked_value, start_index, end_index FROM findings WHERE file_id = ?", (file_id,))
        findings_rows = cursor.fetchall()
        
        findings_list = []
        entity_summary = {}
        max_conf = 0
        
        for fr in findings_rows:
            conf = fr["confidence"]
            if conf > max_conf: max_conf = conf
            etype = fr["entity_type"]
            entity_summary[etype] = entity_summary.get(etype, 0) + 1
            total_findings += 1
            
        risk_level = "LOW"
        if max_conf >= 0.85: 
            risk_level = "CRITICAL"
            risk_CRITICAL += 1
        elif max_conf >= 0.70: 
            risk_level = "HIGH"
            risk_HIGH += 1
        elif max_conf >= 0.50: 
            risk_level = "MEDIUM"

        flagged_files.append({
            "file_id": file_id,
            "modified_time": f["modified_time"],
            "risk_score": max_conf,
            "risk_level": risk_level,
            "total_findings": len(findings_rows),
            "findings": entity_summary
        })

    # Get global entity breakdown
    cursor.execute("SELECT entity_type, count(*) FROM findings GROUP BY entity_type")
    entity_rows = cursor.fetchall()
    global_entity_breakdown = { r["entity_type"]: r["count(*)"] for r in entity_rows }

    # Summary stats
    cursor.execute("SELECT count(*) FROM scan_results")
    total_scanned = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "scan_summary": {
            "total_files_scanned": total_scanned,
            "total_flagged_files": len(flagged_files),
            "total_pii_findings": total_findings,
            "risk_breakdown": { "CRITICAL": risk_CRITICAL, "HIGH": risk_HIGH },
            "entity_breakdown": global_entity_breakdown,
            "scan_start_timestamp": "LIVE (DB-MODE)",
            "scan_duration_seconds": 0
        },
        "flagged_files": flagged_files
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["stats", "results"], default="stats")
    args = parser.parse_args()
    
    if args.mode == "stats":
        print(json.dumps(get_stats()))
    else:
        print(json.dumps(get_results()))
