"""Shared cloud scan routines for manual and scheduled runs."""

import shutil
import subprocess
import threading
from datetime import datetime, timezone
from typing import Any, Dict

from engine.processor import process_scans


_SCAN_LOCK = threading.Lock()


def _scan_aws(config: Dict[str, Any]):
    import boto3
    from aws.aws_checks import (
        check_bucket_acl_public,
        check_bucket_policy_public,
        check_block_public_access,
        check_encryption,
        check_logging,
        check_versioning,
    )

    region = config.get("region") or "us-east-1"
    access_key = (config.get("access_key") or "").strip()
    secret_key = (config.get("secret_key") or "").strip()
    session_token = (config.get("session_token") or "").strip()
    use_env = bool(config.get("use_env", False))

    if not use_env and (not access_key or not secret_key):
        raise ValueError("AWS IAM access key ID and secret access key are required.")

    kwargs = {"region_name": region}
    if not use_env:
        kwargs["aws_access_key_id"] = access_key
        kwargs["aws_secret_access_key"] = secret_key
        if session_token:
            kwargs["aws_session_token"] = session_token

    s3 = boto3.client("s3", **kwargs)
    bucket_names = [bucket["Name"] for bucket in s3.list_buckets().get("Buckets", [])]
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw_records = []

    for bucket in bucket_names:
        encryption = check_encryption(s3, bucket)
        logging = check_logging(s3, bucket)
        versioning = check_versioning(s3, bucket)
        block_public_access = check_block_public_access(s3, bucket)
        policy = check_bucket_policy_public(s3, bucket)
        public_acl = check_bucket_acl_public(s3, bucket)
        public_read = (policy["effective_public_read"] or public_acl) and not block_public_access
        public_write = policy["effective_public_write"] and not block_public_access

        raw_records.append({
            "provider": "aws",
            "bucket_name": bucket,
            "scan_time": scan_time,
            "block_public_access": block_public_access,
            "effective_public_read": public_read,
            "effective_public_write": public_write,
            "encryption_enabled": encryption,
            "logging_enabled": logging,
            "versioning_enabled": versioning,
            "wildcard_principal": policy["wildcard_principal"],
            "public_acl_detected": public_acl,
            "overly_permissive_iam": [],
            "raw_evidence": f"Policy: {policy['raw_policy']} | Public ACL: {public_acl}",
        })

    return raw_records


def _ensure_gcp_adc():
    from google.auth import default as google_auth_default
    from google.auth.exceptions import DefaultCredentialsError

    try:
        google_auth_default()
        return
    except DefaultCredentialsError:
        gcloud = shutil.which("gcloud")
        if not gcloud:
            raise RuntimeError(
                "Google credentials are not configured and the gcloud CLI was not found. Install the Google Cloud CLI and try again."
            )

    # This opens Google's consent flow on the machine running the local scanner.
    login = subprocess.run(
        [gcloud, "auth", "application-default", "login"],
        check=False,
    )
    if login.returncode != 0:
        raise RuntimeError("Google authorization did not complete. Finish sign-in in the browser and try again.")
    google_auth_default()


def _scan_gcp(config: Dict[str, Any]):
    project_id = (config.get("project_id") or "").strip()
    if not project_id:
        raise ValueError("Google Cloud Project ID is required.")

    _ensure_gcp_adc()
    from gcp.gcp_scanner import scan_gcp_storage_buckets

    return scan_gcp_storage_buckets(project_id=project_id)


def run_scan(provider: str, config: Dict[str, Any]):
    """Run one scan and persist its results; serialize runs to protect drift ordering."""
    provider = provider.lower()
    if provider not in {"aws", "gcp"}:
        raise ValueError("Provider must be 'aws' or 'gcp'.")

    with _SCAN_LOCK:
        raw_records = _scan_aws(config) if provider == "aws" else _scan_gcp(config)
        analysis = process_scans(raw_records)

    return {
        "success": True,
        "provider": provider,
        "total_scanned": len(raw_records),
        "raw_records": raw_records,
        "analysis": analysis,
    }
