import os
import json
import pytest
from engine.database import ScanDatabase
from engine.scoring import evaluate_bucket_security
from engine.processor import process_scans

@pytest.fixture
def temp_db(tmp_path):
    """Provides an isolated SQLite database for each test run."""
    db_file = tmp_path / "test_scans.db"
    # Temporarily patch or point ScanDatabase to this path
    db = ScanDatabase(db_path=str(db_file))
    return db

def test_secure_bucket_scoring():
    record = {
        "provider": "aws",
        "bucket_name": "company-prod-secure-logs",
        "scan_time": "2026-11-10T10:00:00Z",
        "block_public_access": True,
        "effective_public_read": False,
        "effective_public_write": False,
        "encryption_enabled": True,
        "logging_enabled": True,
        "versioning_enabled": True,
        "wildcard_principal": False,
        "public_acl_detected": False,
        "overly_permissive_iam": []
    }
    
    score, severity, findings = evaluate_bucket_security(record)
    assert score == 0
    assert severity == "info"
    assert len(findings) == 0

def test_critical_public_bucket_scoring():
    record = {
        "provider": "aws",
        "bucket_name": "marketing-public-assets",
        "scan_time": "2026-11-10T10:00:00Z",
        "block_public_access": False,
        "effective_public_read": True,
        "effective_public_write": False,
        "encryption_enabled": False,
        "logging_enabled": False,
        "versioning_enabled": False,
        "wildcard_principal": True,
        "public_acl_detected": True,
        "overly_permissive_iam": []
    }
    
    score, severity, findings = evaluate_bucket_security(record)
    assert score >= 75
    assert severity == "critical"
    
    finding_ids = [f["id"] for f in findings]
    assert "CLOUD_PUBLIC_READ" in finding_ids
    assert "CLOUD_UNENCRYPTED" in finding_ids
    assert "CLOUD_LOGGING_DISABLED" in finding_ids

def test_gcp_bucket_scoring():
    record = {
        "provider": "gcp",
        "bucket_name": "data-science-backup-gcp",
        "scan_time": "2026-11-10T10:00:00Z",
        "block_public_access": False,
        "effective_public_read": True,
        "effective_public_write": True,
        "encryption_enabled": True,
        "logging_enabled": False,
        "versioning_enabled": False,
        "wildcard_principal": True,
        "public_acl_detected": False,
        "overly_permissive_iam": []
    }
    
    score, severity, findings = evaluate_bucket_security(record)
    assert score >= 75
    assert severity == "critical"
    
    finding_ids = [f["id"] for f in findings]
    assert "CLOUD_PUBLIC_READ" in finding_ids
    assert "CLOUD_PUBLIC_WRITE" in finding_ids

def test_processor_pipeline_and_drift(monkeypatch, tmp_path):
    # Mock database path in processor module
    db_path = tmp_path / "pipeline_test.db"
    monkeypatch.setattr("engine.processor.ScanDatabase", lambda: ScanDatabase(db_path=str(db_path)))

    # Scan 1: Secure state
    scan_day_1 = [
        {
            "provider": "aws",
            "bucket_name": "app-data-bucket",
            "scan_time": "2026-11-09T10:00:00Z",
            "block_public_access": True,
            "effective_public_read": False,
            "effective_public_write": False,
            "encryption_enabled": True,
            "logging_enabled": True,
            "versioning_enabled": True,
            "wildcard_principal": False,
            "public_acl_detected": False,
            "overly_permissive_iam": []
        }
    ]

    result_day_1 = process_scans(scan_day_1)
    assert result_day_1[0]["risk_score"] == 0
    assert result_day_1[0]["drift"]["changed"] is False

    # Scan 2: Misconfigured state (bucket becomes public)
    scan_day_2 = [
        {
            "provider": "aws",
            "bucket_name": "app-data-bucket",
            "scan_time": "2026-11-10T10:00:00Z",
            "block_public_access": False,
            "effective_public_read": True,
            "effective_public_write": False,
            "encryption_enabled": True,
            "logging_enabled": True,
            "versioning_enabled": True,
            "wildcard_principal": True,
            "public_acl_detected": True,
            "overly_permissive_iam": []
        }
    ]

    result_day_2 = process_scans(scan_day_2)
    assert result_day_2[0]["risk_score"] > 0
    assert result_day_2[0]["drift"]["changed"] is True
    assert result_day_2[0]["drift"]["change"] == "private -> public"