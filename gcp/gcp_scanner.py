"""
Cloud Security Scanner — GCP Module Orchestrator (Person 2)
Discovers GCS buckets, runs comprehensive security configuration checks,
evaluates effective public exposure across multiple layers, and normalizes
findings into the shared contract for downstream analysis.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .gcp_access import get_storage_client, list_storage_buckets
from .gcp_checks import (
    check_encryption,
    check_logging,
    check_versioning,
    check_public_access_prevention,
    check_uniform_bucket_level_access,
    check_iam_policy_public,
    check_bucket_acl_public,
)


def evaluate_bucket_security(bucket: Any) -> Dict[str, Any]:
    """
    Executes all security checks on a single GCP Cloud Storage bucket
    and computes the effective public access and evaluation certainty.

    Returns:
        Dict conforming to the normalized multi-cloud security schema.
    """
    scan_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bucket_name = getattr(bucket, "name", str(bucket))

    # 1. Granular security configuration collection
    encryption_info = check_encryption(bucket)
    logging_info = check_logging(bucket)
    versioning_info = check_versioning(bucket)
    pap_info = check_public_access_prevention(bucket)
    ubla_info = check_uniform_bucket_level_access(bucket)

    ubla_enabled = ubla_info.get("ubla_enabled", False)
    pap_enabled = pap_info.get("pap_enabled", False)
    pap_status = pap_info.get("status", "unspecified")

    # 2. IAM and ACL policy collection
    iam_info = check_iam_policy_public(bucket)
    acl_info = check_bucket_acl_public(bucket, ubla_enabled)

    # 3. Multi-layer Effective Public Access Evaluation
    effective_public_read = False
    effective_public_write = False
    read_status = "DEFINITIVE_PRIVATE"
    write_status = "DEFINITIVE_PRIVATE"
    overall_status = "DEFINITIVE"

    evidence_parts: List[str] = []
    overly_permissive_iam: List[Dict[str, Any]] = []

    # Evidence: PAP & UBLA
    evidence_parts.append(f"PAP: {pap_status}")
    evidence_parts.append(f"UBLA: {'enabled' if ubla_enabled else 'disabled'}")

    if pap_enabled:
        # Rule 1: Public Access Prevention enforced blocks all public access
        effective_public_read = False
        effective_public_write = False
        read_status = "DEFINITIVE_PRIVATE"
        write_status = "DEFINITIVE_PRIVATE"
        overall_status = "DEFINITIVE"
        evidence_parts.append("PAP enforced: all public access is blocked by GCP infrastructure guardrail")

        if iam_info.get("wildcard_principal") or acl_info.get("public_acl_detected"):
            evidence_parts.append("Note: Public IAM/ACL grants exist but are overridden and nullified by enforced PAP")
            for binding in iam_info.get("public_bindings", []):
                overly_permissive_iam.append({
                    "role": binding.get("role"),
                    "members": binding.get("members"),
                    "status": "nullified_by_pap"
                })

    elif iam_info.get("access_denied"):
        # Rule 2: 403 Forbidden on IAM Policy retrieval
        # Without PAP enforced and without IAM policy visibility, privacy cannot be established
        effective_public_read = False
        effective_public_write = False
        read_status = "INCONCLUSIVE_IAM_PERMISSION_DENIED"
        write_status = "INCONCLUSIVE_IAM_PERMISSION_DENIED"
        overall_status = "INCONCLUSIVE"
        evidence_parts.append(f"IAM Check: {iam_info.get('error_message')}")

    else:
        # Rule 3: PAP not enforced, IAM policy successfully inspected
        unconditional_iam_read = iam_info.get("public_read_unconditional", False)
        unconditional_iam_write = iam_info.get("public_write_unconditional", False)
        acl_read = acl_info.get("public_read_acl", False)
        acl_write = acl_info.get("public_write_acl", False)

        has_conditional_bindings = bool(iam_info.get("conditional_bindings"))
        has_custom_roles = bool(iam_info.get("custom_roles_detected"))

        # Evaluate Public Read
        if unconditional_iam_read or acl_read:
            effective_public_read = True
            read_status = "DEFINITIVE_PUBLIC"
            source = "IAM" if unconditional_iam_read else "Legacy ACL"
            evidence_parts.append(f"Public Read: Confirmed via {source}")
        elif has_conditional_bindings:
            effective_public_read = False
            read_status = "CONDITIONAL_PUBLIC"
            overall_status = "CONDITIONAL"
            evidence_parts.append(f"Public Read: Conditional public IAM binding present ({len(iam_info['conditional_bindings'])} condition(s))")
        elif has_custom_roles:
            effective_public_read = False
            read_status = "INCONCLUSIVE_CUSTOM_ROLE"
            overall_status = "INCONCLUSIVE"
            evidence_parts.append(f"Public Read: Inconclusive; public principal granted unverified custom role(s): {iam_info['custom_roles_detected']}")
        elif not ubla_enabled:
            effective_public_read = False
            read_status = "INCONCLUSIVE_LEGACY_ACLS"
            overall_status = "INCONCLUSIVE"
            evidence_parts.append("Public Read: UBLA disabled; individual object ACLs may grant unverified public access")
        elif pap_status == "inherited":
            effective_public_read = False
            read_status = "INCONCLUSIVE_INHERITED_PAP"
            overall_status = "INCONCLUSIVE"
            evidence_parts.append("Public Read: PAP is inherited from organization policy; org-level enforcement unverified")
        else:
            effective_public_read = False
            read_status = "DEFINITIVE_PRIVATE"
            evidence_parts.append("Public Read: No public grants found")

        # Evaluate Public Write
        if unconditional_iam_write or acl_write:
            effective_public_write = True
            write_status = "DEFINITIVE_PUBLIC"
            source = "IAM" if unconditional_iam_write else "Legacy ACL"
            evidence_parts.append(f"Public Write: Confirmed via {source}")
        elif has_conditional_bindings:
            effective_public_write = False
            write_status = "CONDITIONAL_PUBLIC"
            overall_status = "CONDITIONAL"
            evidence_parts.append(f"Public Write: Conditional public IAM binding present")
        elif has_custom_roles:
            effective_public_write = False
            write_status = "INCONCLUSIVE_CUSTOM_ROLE"
            overall_status = "INCONCLUSIVE"
            evidence_parts.append(f"Public Write: Inconclusive; public principal granted unverified custom role(s)")
        elif not ubla_enabled:
            effective_public_write = False
            write_status = "INCONCLUSIVE_LEGACY_ACLS"
            overall_status = "INCONCLUSIVE"
            evidence_parts.append("Public Write: UBLA disabled; object-level write permissions unverified")
        elif pap_status == "inherited":
            effective_public_write = False
            write_status = "INCONCLUSIVE_INHERITED_PAP"
            overall_status = "INCONCLUSIVE"
            evidence_parts.append("Public Write: PAP is inherited; org-level enforcement unverified")
        else:
            effective_public_write = False
            write_status = "DEFINITIVE_PRIVATE"
            evidence_parts.append("Public Write: No public write grants found")

        # Populate overly permissive IAM entries
        for binding in iam_info.get("public_bindings", []):
            overly_permissive_iam.append({
                "role": binding.get("role"),
                "members": binding.get("members"),
                "condition": binding.get("condition"),
                "status": "conditional" if binding.get("condition") else "active"
            })

    # Evidence: Encryption, Versioning, Logging
    evidence_parts.append(f"Encryption: {encryption_info.get('raw_encryption')}")
    evidence_parts.append(f"Versioning: {'enabled' if versioning_info.get('versioning_enabled') else 'disabled'}")
    if logging_info.get("logging_enabled"):
        evidence_parts.append(f"Logging: enabled (target: {logging_info.get('log_bucket')})")
    else:
        evidence_parts.append("Logging: disabled")

    raw_evidence_str = " | ".join(evidence_parts)

    # 4. Construct normalized JSON record matching the shared multi-cloud contract
    record: Dict[str, Any] = {
        "provider": "gcp",
        "bucket_name": bucket_name,
        "scan_time": scan_timestamp,
        "block_public_access": pap_enabled,
        "effective_public_read": effective_public_read,
        "effective_public_write": effective_public_write,
        "encryption_enabled": encryption_info.get("encryption_enabled", True),
        "logging_enabled": logging_info.get("logging_enabled", False),
        "versioning_enabled": versioning_info.get("versioning_enabled", False),
        "wildcard_principal": iam_info.get("wildcard_principal", False) or acl_info.get("public_acl_detected", False),
        "public_acl_detected": acl_info.get("public_acl_detected", False),
        "overly_permissive_iam": overly_permissive_iam,
        "raw_evidence": raw_evidence_str,
        # High-fidelity GCP evaluation metadata
        "gcp_details": {
            "access_evaluation_status": {
                "overall_status": overall_status,
                "read_status": read_status,
                "write_status": write_status,
                "definitive": overall_status == "DEFINITIVE"
            },
            "public_access_prevention": pap_status,
            "uniform_bucket_level_access": ubla_enabled,
            "cmek_enabled": encryption_info.get("cmek_enabled", False),
            "cmek_key_name": encryption_info.get("kms_key_name"),
            "all_authenticated_users_detected": iam_info.get("all_authenticated_users_detected", False) or acl_info.get("all_authenticated_users", False),
            "all_users_detected": iam_info.get("all_users_detected", False) or ("allUsers" in acl_info.get("details", "")),
            "conditional_bindings_count": len(iam_info.get("conditional_bindings", [])),
            "legacy_acls_active": not ubla_enabled
        }
    }

    return record


def scan_gcp_storage_buckets(project_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Discovers GCP Cloud Storage buckets within the specified or active project,
    runs security configuration audits, and returns a list of normalized
    security findings for downstream analysis engines.

    Args:
        project_id: Optional GCP project ID. If not supplied, falls back to
                    ADC project or GOOGLE_CLOUD_PROJECT / GCP_PROJECT_ID environment variable.

    Returns:
        List of normalized security finding dictionaries.
    """
    client, resolved_project = get_storage_client(project_id=project_id)
    if not client:
        print("[-] Aborting GCP scan: Unable to initialize Google Cloud Storage client.")
        return []

    print(f"[+] Initialized GCP Storage client for project: '{resolved_project or 'auto-detected'}'")
    buckets = list_storage_buckets(client, project_id=resolved_project)
    print(f"[+] Discovered {len(buckets)} GCS bucket(s). Starting security audit...")

    scan_results: List[Dict[str, Any]] = []

    for bucket in buckets:
        bucket_name = getattr(bucket, "name", str(bucket))
        print(f"    Scanning GCS bucket: {bucket_name}...")
        record = evaluate_bucket_security(bucket)
        scan_results.append(record)

    return scan_results


def main() -> None:
    """CLI execution entrypoint."""
    import sys
    target_project = sys.argv[1] if len(sys.argv) > 1 else None
    results = scan_gcp_storage_buckets(project_id=target_project)

    print("\n[+] GCP Scan Complete. Normalized JSON Output:")
    print(json.dumps(results, indent=2))

    output_filename = "gcp_scan_output.json"
    with open(output_filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Saved GCP scan results to {output_filename}")


if __name__ == "__main__":
    main()

