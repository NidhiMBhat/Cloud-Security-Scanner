# engine/database.py

import sqlite3
import json

class ScanDatabase:
    def __init__(self, db_path="scans.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bucket_name TEXT,
                    provider TEXT,
                    scan_time TEXT,
                    risk_score INTEGER,
                    severity TEXT,
                    findings_json TEXT,
                    effective_public_read BOOLEAN
                )
            """)
            conn.commit()

    def get_previous_scan(self, bucket_name: str):
        """Retrieves the most recent prior scan for drift comparison."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT risk_score, effective_public_read, severity 
                FROM scan_history 
                WHERE bucket_name = ? 
                ORDER BY id DESC LIMIT 1
            """, (bucket_name,))
            row = cursor.fetchone()
            if row:
                return {
                    "risk_score": row[0],
                    "effective_public_read": row[1],
                    "severity": row[2]
                }
            return None

    def save_scan(self, bucket_name: str, provider: str, scan_time: str, risk_score: int, severity: str, findings: list, effective_public_read: bool):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO scan_history (bucket_name, provider, scan_time, risk_score, severity, findings_json, effective_public_read)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (bucket_name, provider, scan_time, risk_score, severity, json.dumps(findings), effective_public_read))
            conn.commit()