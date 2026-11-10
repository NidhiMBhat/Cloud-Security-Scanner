"""
Cloud Security Scanner — Unified Python Backend API Server
Provides REST endpoints for scanning AWS/GCP, running scoring analysis,
querying scan history, and serving the React frontend.
"""

import json
import os
import sys
import urllib.parse
from datetime import datetime
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

# Ensure project root is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from engine.processor import process_scans
from backend.scan_service import run_scan


class ScannerAPIHandler(SimpleHTTPRequestHandler):
    """Handles REST API calls and serves static React frontend files."""

    def __init__(self, *args, **kwargs):
        # Serve frontend static assets from web/ or root
        super().__init__(*args, directory=os.path.join(ROOT_DIR, "web"), **kwargs)

    def _send_json(self, data: Any, status: int = 200):
        response_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(response_bytes)

    def _send_error(self, message: str, status: int = 400):
        self._send_json({"error": message, "success": False}, status=status)

    def do_OPTIONS(self):
        """Handle CORS pre-flight."""
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            self.handle_status()
        elif path == "/api/history":
            self.handle_get_history()
        elif path == "/api/sample-data":
            self.handle_sample_data()
        elif path.startswith("/api/"):
            self._send_error(f"API endpoint not found: {path}", status=404)
        else:
            # Fallback to SPA index.html for unknown frontend routes
            file_path = os.path.join(ROOT_DIR, "web", path.lstrip("/"))
            if not os.path.exists(file_path) or os.path.isdir(file_path):
                self.path = "/index.html"
            super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Read JSON body
        content_length = int(self.headers.get("Content-Length", 0))
        body = {}
        if content_length > 0:
            raw_body = self.rfile.read(content_length).decode("utf-8")
            try:
                body = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_error("Invalid JSON body", status=400)
                return

        if path == "/api/scan/aws":
            self.handle_scan_aws(body)
        elif path == "/api/scan/gcp":
            self.handle_scan_gcp(body)
        elif path == "/api/analyze":
            self.handle_analyze_upload(body)
        elif path == "/api/clear-history":
            self.handle_clear_history()
        else:
            self._send_error(f"Endpoint not found: {path}", status=404)

    # ──────────────────────────────────────────────────────────────────────────
    # API HANDLERS
    # ──────────────────────────────────────────────────────────────────────────

    def handle_status(self):
        """Checks local cloud SDK availability and database health."""
        aws_sdk = False
        gcp_sdk = False
        try:
            import boto3
            aws_sdk = True
        except ImportError:
            pass

        try:
            from google.cloud import storage
            gcp_sdk = True
        except ImportError:
            pass

        db_path = os.path.join(ROOT_DIR, "scans.db")
        db_exists = os.path.exists(db_path)

        self._send_json({
            "status": "online",
            "server_time": datetime.utcnow().isoformat() + "Z",
            "providers": {
                "aws": {"installed": aws_sdk, "name": "Amazon Web Services (S3)"},
                "gcp": {"installed": gcp_sdk, "name": "Google Cloud Storage (GCS)"}
            },
            "database": {"connected": True, "path": db_path, "exists": db_exists},
        })

    def handle_scan_aws(self, body: Dict[str, Any]):
        """Executes AWS S3 security scan using provided credentials."""
        try:
            result = run_scan("aws", {
                "region": body.get("region", "us-east-1"),
                "access_key": (body.get("access_key") or "").strip(),
                "secret_key": (body.get("secret_key") or "").strip(),
                "session_token": (body.get("session_token") or "").strip(),
                "use_env": body.get("use_env", False),
            })
            self._send_json(result)
        except (TypeError, ValueError) as e:
            self._send_error(str(e), status=400)
        except Exception as e:
            self._send_error(f"AWS Scan Failed: {str(e)}", status=500)

    def handle_scan_gcp(self, body: Dict[str, Any]):
        """Authorize with local Google credentials if needed, then scan GCS."""
        try:
            result = run_scan("gcp", {"project_id": (body.get("project_id") or "").strip()})
            self._send_json(result)
        except ValueError as e:
            self._send_error(str(e), status=400)
        except Exception as e:
            self._send_error(f"GCP Scan Failed: {str(e)}", status=500)

    def handle_analyze_upload(self, body: Dict[str, Any]):
        """Processes an uploaded raw JSON scan file."""
        records = body.get("records", [])
        if isinstance(body, list):
            records = body
        elif isinstance(records, dict):
            records = [records]

        if not records or not isinstance(records, list):
            self._send_error("Invalid records array. Please provide a list of bucket scan objects.")
            return

        try:
            analysis_output = process_scans(records)
            self._send_json({
                "success": True,
                "total_scanned": len(records),
                "raw_records": records,
                "analysis": analysis_output
            })
        except Exception as e:
            self._send_error(f"Analysis Engine Error: {str(e)}", status=500)

    def handle_get_history(self):
        """Retrieves scan history from SQLite database."""
        try:
            import sqlite3
            db_path = os.path.join(ROOT_DIR, "scans.db")
            if not os.path.exists(db_path):
                self._send_json({"records": [], "count": 0})
                return

            with sqlite3.connect(db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, bucket_name, provider, scan_time, risk_score, severity,
                           findings_json, effective_public_read
                    FROM scan_history
                    ORDER BY id DESC
                    LIMIT 300
                """)
                rows = cursor.fetchall()

                records = []
                for row in rows:
                    findings = []
                    try:
                        findings = json.loads(row["findings_json"])
                    except Exception:
                        pass

                    records.append({
                        "id": row["id"],
                        "bucket_name": row["bucket_name"],
                        "provider": row["provider"],
                        "scan_time": row["scan_time"],
                        "risk_score": row["risk_score"],
                        "severity": row["severity"],
                        "findings": findings,
                        "effective_public_read": bool(row["effective_public_read"])
                    })

                self._send_json({"records": records, "count": len(records)})

        except Exception as e:
            self._send_error(f"Failed to fetch history: {str(e)}", status=500)

    def handle_clear_history(self):
        """Clears scan history table."""
        try:
            import sqlite3
            db_path = os.path.join(ROOT_DIR, "scans.db")
            if os.path.exists(db_path):
                with sqlite3.connect(db_path) as conn:
                    conn.execute("DELETE FROM scan_history")
                    conn.commit()
            self._send_json({"success": True, "message": "History cleared successfully"})
        except Exception as e:
            self._send_error(f"Failed to clear history: {str(e)}", status=500)

    def handle_sample_data(self):
        """Provides high-quality realistic sample scan data for instant testing."""
        sample_records = [
            {
                "provider": "aws",
                "bucket_name": "prod-customer-documents-2026",
                "scan_time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "block_public_access": False,
                "effective_public_read": True,
                "effective_public_write": False,
                "encryption_enabled": False,
                "logging_enabled": False,
                "versioning_enabled": False,
                "wildcard_principal": True,
                "public_acl_detected": True,
                "overly_permissive_iam": [
                    {"role": "s3:GetObject", "members": ["*"], "status": "active"}
                ],
                "raw_evidence": "Policy Statement allows Principal: '*' for Action: ['s3:GetObject'] | Public ACL Detected: AllUsers Read grant"
            },
            {
                "provider": "gcp",
                "bucket_name": "gcs-analytics-export-warehouse",
                "scan_time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "block_public_access": False,
                "effective_public_read": False,
                "effective_public_write": True,
                "encryption_enabled": True,
                "logging_enabled": False,
                "versioning_enabled": True,
                "wildcard_principal": True,
                "public_acl_detected": False,
                "overly_permissive_iam": [
                    {"role": "roles/storage.objectCreator", "members": ["allUsers"], "status": "active"}
                ],
                "raw_evidence": "PAP: unspecified | IAM Binding allows allUsers role roles/storage.objectCreator | UBLA: enabled | Encryption: AES-256",
                "gcp_details": {
                    "access_evaluation_status": {"overall_status": "DEFINITIVE", "read_status": "DEFINITIVE_PRIVATE", "write_status": "DEFINITIVE_PUBLIC", "definitive": True},
                    "public_access_prevention": "unspecified",
                    "uniform_bucket_level_access": True,
                    "cmek_enabled": False,
                    "all_users_detected": True
                }
            },
            {
                "provider": "aws",
                "bucket_name": "app-static-assets-cdn-cache",
                "scan_time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "block_public_access": True,
                "effective_public_read": False,
                "effective_public_write": False,
                "encryption_enabled": True,
                "logging_enabled": True,
                "versioning_enabled": True,
                "wildcard_principal": False,
                "public_acl_detected": False,
                "overly_permissive_iam": [],
                "raw_evidence": "BlockPublicAccess: Enabled | SSE-S3 AES256: Enabled | AccessLogging Target: audit-logs-bucket"
            },
            {
                "provider": "gcp",
                "bucket_name": "finance-backup-vault-coldline",
                "scan_time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "block_public_access": True,
                "effective_public_read": False,
                "effective_public_write": False,
                "encryption_enabled": True,
                "logging_enabled": True,
                "versioning_enabled": True,
                "wildcard_principal": False,
                "public_acl_detected": False,
                "overly_permissive_iam": [],
                "raw_evidence": "PAP: enforced | CMEK enabled with Cloud KMS key: projects/fin-prod/locations/us/keyRings/vault/cryptoKeys/primary | UBLA: enabled",
                "gcp_details": {
                    "access_evaluation_status": {"overall_status": "DEFINITIVE", "read_status": "DEFINITIVE_PRIVATE", "write_status": "DEFINITIVE_PRIVATE", "definitive": True},
                    "public_access_prevention": "enforced",
                    "uniform_bucket_level_access": True,
                    "cmek_enabled": True,
                    "cmek_key_name": "projects/fin-prod/locations/us/keyRings/vault/cryptoKeys/primary",
                    "all_users_detected": False
                }
            }
        ]

        analysis = process_scans(sample_records)
        self._send_json({
            "success": True,
            "provider": "multi-cloud",
            "total_scanned": len(sample_records),
            "raw_records": sample_records,
            "analysis": analysis
        })


def run_server(port: int = 8000, host: str = "127.0.0.1"):
    web_dir = os.path.join(ROOT_DIR, "web")
    os.makedirs(web_dir, exist_ok=True)
    server = ThreadingHTTPServer((host, port), ScannerAPIHandler)
    print(f"===============================================================")
    print(f"  Cloud Security Scanner — Enterprise React Backend API")
    print(f"  URL: http://localhost:{port}")
    print(f"  API Docs: http://localhost:{port}/api/status")
    print(f"===============================================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Server gracefully stopped.")
        server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run_server(port=port)

