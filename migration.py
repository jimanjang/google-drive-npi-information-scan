import json
import sqlite3
import os
import re
from pathlib import Path

# Paths
TARGET_DIR = Path(r"C:\Users\user\.antigravity\google drive scan for microsoft presidio")
JSON_FILE = TARGET_DIR / "scan_cache.json"
DB_FILE = TARGET_DIR / "scan_cache.db"

def deep_recovery():
    if not JSON_FILE.exists():
        print(f"Error: {JSON_FILE} not found.")
        return

    print(f"Starting deep recovery from {JSON_FILE} (~150MB+)...")
    with open(JSON_FILE, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    # Pattern to find potential JSON fragments for each file record
    # Basic structure: "FILE_ID": { ... }
    # Google Drive File IDs are usually 28-44 chars alphanumeric with _ and -
    pattern = re.compile(r'"(?P<id>[a-zA-Z0-9_-]{25,})":\s*\{')
    
    matches = list(pattern.finditer(content))
    print(f"Found {len(matches)} potential file records in the corrupted JSON.")

    print(f"Connecting to {DB_FILE}...")
    # Keep existing DB if it exists (for incremental safety)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS scan_results (
            file_id TEXT PRIMARY KEY,
            modified_time TEXT,
            total_chars INTEGER,
            error TEXT,
            last_scanned TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id TEXT,
            entity_type TEXT,
            confidence REAL,
            masked_value TEXT,
            start_index INTEGER,
            end_index INTEGER,
            FOREIGN KEY (file_id) REFERENCES scan_results(file_id)
        );
        CREATE INDEX IF NOT EXISTS idx_findings_file_id ON findings(file_id);
    ''')

    success_count = 0
    error_count = 0
    finding_count = 0

    for i, m in enumerate(matches):
        file_id = m.group('id')
        start_pos = m.start()
        
        # Determine the search window for the closing brace
        # Usually a record is < 10KB, but let's take 50KB to be safe
        end_search = min(start_pos + 50000, len(content))
        window = content[start_pos:end_search]
        
        # Try to find the matching closing brace for this file's object
        # We look for the first '}' followed by either ',' or '}' (end of whole JSON)
        # or the brace that balances the record.
        
        brace_count = 0
        found_end = -1
        # Simple brace balancer for the record object
        # We start at the '{' which is after the file_id
        # "id": { ... }
        # start_pos is at the first quote of the id
        record_start = window.find('{')
        if record_start == -1: continue
        
        for idx in range(record_start, len(window)):
            if window[idx] == '{': brace_count += 1
            if window[idx] == '}': brace_count -= 1
            if brace_count == 0:
                found_end = idx
                break
        
        if found_end != -1:
            fragment = "{" + window[0:found_end+1] + "}"
            try:
                # Wrap it in {} to make it a valid JSON object {"id": {...}}
                data_wrap = json.loads(fragment)
                data = data_wrap.get(file_id)
                
                if data and isinstance(data, dict):
                    # Insert into DB
                    cursor.execute(
                        "INSERT OR REPLACE INTO scan_results (file_id, modified_time, total_chars, error) VALUES (?, ?, ?, ?)",
                        (file_id, data.get("modified_time"), data.get("total_chars"), data.get("error"))
                    )
                    
                    # Manage findings
                    # First clear old findings if this is a REPLACE
                    cursor.execute("DELETE FROM findings WHERE file_id = ?", (file_id,))
                    
                    findings = data.get("findings", [])
                    for f in findings:
                        cursor.execute(
                            "INSERT INTO findings (file_id, entity_type, confidence, masked_value, start_index, end_index) VALUES (?, ?, ?, ?, ?, ?)",
                            (file_id, f.get("entity_type"), f.get("confidence"), f.get("masked_value"), f.get("start"), f.get("end"))
                        )
                        finding_count += 1
                    
                    success_count += 1
            except Exception:
                error_count += 1
        else:
            error_count += 1

        if (i+1) % 1000 == 0:
            print(f"  Processed {i+1} fragments... (Success: {success_count}, Errors: {error_count})")
            conn.commit()

    conn.commit()
    conn.close()
    
    print(f"\nDEEP RECOVERY COMPLETE:")
    print(f" - Valid fragments recovered: {success_count}")
    print(f" - Corrupted fragments skipped: {error_count}")
    print(f" - Total PII findings migrated: {finding_count}")
    print(f" - Destination: {DB_FILE}")

if __name__ == "__main__":
    deep_recovery()
