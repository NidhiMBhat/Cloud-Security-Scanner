# GCP Module Integration Guide

**For:** Person 3 (Risk Scoring & CIS Mapping) and Person 4 (API, Dashboard & Reporting)  
**Author:** Person 2 (GCP Module Lead)  
**Status:** Ready for Integration  

---

## 1. Quick Start: Invoking the GCP Collector

The GCP scanner provides an in-memory entry point identical in style to Person 1's AWS scanner:

```python
from gcp.gcp_scanner import scan_gcp_storage_buckets

# Auto-detects GCP project from ADC credentials / environment:
gcp_findings = scan_gcp_storage_buckets()

# Or specify a targeted GCP Project ID:
gcp_findings = scan_gcp_storage_buckets(project_id="my-production-project")
```

Both `scan_aws_s3_buckets()` and `scan_gcp_storage_buckets()` return a Python `List[Dict[str, Any]]`.

---

## 2. Multi-Cloud Normalization Contract

Every bucket finding dictionary is guaranteed to contain the following top-level keys:

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `provider` | `str` | `"gcp"` for GCP findings (`"aws"` for S3). |
| `bucket_name` | `str` | Unique bucket identifier. |
| `scan_time` | `str` | UTC ISO-8601 timestamp (`%Y-%m-%dT%H:%M:%SZ`). |
| `block_public_access` | `bool` | `True` if GCP Public Access Prevention (PAP) is enforced. |
| `effective_public_read` | `bool` | `True` if bucket is unconditionally readable by public principals. |
| `effective_public_write` | `bool` | `True` if bucket is unconditionally writable by public principals. |
| `encryption_enabled` | `bool` | `True` (always `True` in GCP; Cloud Storage encrypts at rest by default). |
| `logging_enabled` | `bool` | `True` if usage logging target bucket is configured. |
| `versioning_enabled` | `bool` | `True` if object versioning is enabled. |
| `wildcard_principal` | `bool` | `True` if `allUsers` or `allAuthenticatedUsers` appears in IAM or ACL. |
| `public_acl_detected` | `bool` | `True` if legacy ACL grants public access (only active if UBLA is off). |
| `overly_permissive_iam` | `list` | List of IAM binding objects with public or excessive privileges. |
| `raw_evidence` | `str` | Human-readable audit trail summarizing all layer determinations. |
| `gcp_details` | `dict` | High-fidelity GCP-specific metadata and evaluation certainty. |

---

## 3. Interpreting Evaluation Certainty (`gcp_details.access_evaluation_status`)

> [!IMPORTANT]
> **Critical Rule for Risk Scoring (Person 3):**  
> Do **NOT** assume that `effective_public_read == False` or `effective_public_write == False` proves a bucket is definitively private.  
> If evaluation is incomplete or blocked, the boolean is set to `False` for backward compatibility, but the machine-readable `access_evaluation_status` indicates whether the finding is definitive or inconclusive.

Inspect `record["gcp_details"]["access_evaluation_status"]`:

```json
{
  "overall_status": "DEFINITIVE",
  "read_status": "DEFINITIVE_PRIVATE",
  "write_status": "DEFINITIVE_PRIVATE",
  "definitive": true
}
```

### Possible Status Values

| Status Enum | Meaning | Downstream Handling (Person 3 / 4) |
| :--- | :--- | :--- |
| `DEFINITIVE_PRIVATE` | Proven private: PAP is enforced, or UBLA is enabled with no public IAM bindings. | Low risk / Pass CIS benchmark. |
| `DEFINITIVE_PUBLIC` | Confirmed public: Unconditional IAM read/write or legacy ACL exposure. | Critical/High risk / Fail CIS benchmark. |
| `CONDITIONAL_PUBLIC` | A public grant (`allUsers`/`allAuthenticatedUsers`) has an IAM Condition expression attached (e.g. date-bounded, resource-tagged, or VPC-restricted). | Medium risk / Flag as "Conditional Exposure" requiring manual review. |
| `INCONCLUSIVE_INHERITED_PAP` | Bucket PAP is set to `inherited`. Bucket-level IAM has no public grant, but organization-level enforcement was not verifiable. | Informational / Recommend setting PAP to `enforced` explicitly. |
| `INCONCLUSIVE_LEGACY_ACLS` | Uniform Bucket-Level Access (UBLA) is disabled. Bucket-level ACLs are private, but individual objects may have public ACLs. | Medium risk / Recommend enabling UBLA to nullify object ACLs. |
| `INCONCLUSIVE_IAM_PERMISSION_DENIED` | Scanner encountered `403 Forbidden` attempting to call `storage.buckets.getIamPolicy`. | Audit Failure / Alert admin to grant `roles/storage.viewer` to auditor identity. |
| `INCONCLUSIVE_CUSTOM_ROLE` | A public principal was granted a custom role whose permissions were unverified. | High risk / Flag custom role for inspection. |

### Explicit Rules for Person 3 Risk Scoring Engine

Person 3's scoring and CIS mapping algorithm should branch as follows:

```python
def compute_risk_score(record: dict) -> dict:
    gcp_details = record.get("gcp_details", {})
    status_block = gcp_details.get("access_evaluation_status", {})
    overall = status_block.get("overall_status", "DEFINITIVE")
    read_status = status_block.get("read_status", "DEFINITIVE_PUBLIC" if record["effective_public_read"] else "DEFINITIVE_PRIVATE")

    if overall == "DEFINITIVE":
        if record["effective_public_read"] or record["effective_public_write"]:
            return {
                "risk_level": "CRITICAL",
                "score": 10.0,
                "cis_status": "FAIL",
                "reason": "Confirmed unconditional public access to bucket"
            }
        else:
            return {
                "risk_level": "LOW",
                "score": 0.0,
                "cis_status": "PASS",
                "reason": "Proven private: PAP enforced or UBLA enabled with no public grants"
            }

    elif overall == "CONDITIONAL":
        return {
            "risk_level": "MEDIUM",
            "score": 5.0,
            "cis_status": "MANUAL_REVIEW_REQUIRED",
            "reason": f"Conditional public grant detected: {record['raw_evidence']}"
        }

    elif overall == "INCONCLUSIVE":
        if read_status == "INCONCLUSIVE_IAM_PERMISSION_DENIED":
            return {
                "risk_level": "HIGH",
                "score": 8.0,
                "cis_status": "AUDIT_FAILED",
                "reason": "Insufficient permissions to inspect bucket IAM policy (403 Forbidden)"
            }
        elif read_status == "INCONCLUSIVE_LEGACY_ACLS":
            return {
                "risk_level": "MEDIUM",
                "score": 4.5,
                "cis_status": "WARN",
                "reason": "UBLA is disabled; individual object-level ACLs may permit public exposure"
            }
        elif read_status == "INCONCLUSIVE_INHERITED_PAP":
            return {
                "risk_level": "LOW_MEDIUM",
                "score": 2.5,
                "cis_status": "WARN",
                "reason": "Public Access Prevention is inherited from org policy; org enforcement uninspected"
            }
        else:
            return {
                "risk_level": "MEDIUM",
                "score": 5.0,
                "cis_status": "INCONCLUSIVE",
                "reason": f"Audit evaluation could not be conclusively determined: {read_status}"
            }
```

---

## 4. Multi-Cloud Ingestion Code Example (For Person 3 & Person 4)

Here is how Person 3 can ingest both providers into the unified Risk Engine:

```python
from typing import List, Dict, Any
from aws.aws_scanner import scan_aws_s3_buckets
from gcp.gcp_scanner import scan_gcp_storage_buckets

def run_multi_cloud_audit(aws_region="us-east-1", gcp_project=None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # 1. Collect AWS S3 findings
    try:
        aws_results = scan_aws_s3_buckets(region_name=aws_region)
        findings.extend(aws_results)
    except Exception as e:
        print(f"[-] AWS scan error: {e}")

    # 2. Collect GCP findings
    try:
        gcp_results = scan_gcp_storage_buckets(project_id=gcp_project)
        findings.extend(gcp_results)
    except Exception as e:
        print(f"[-] GCP scan error: {e}")

    return findings

# Example consumption
if __name__ == "__main__":
    all_findings = run_multi_cloud_audit()
    print(f"Audited {len(all_findings)} total cloud buckets.")
    
    for f in all_findings:
        provider = f["provider"]
        name = f["bucket_name"]
        pub_read = f["effective_public_read"]
        
        # Safe access to GCP certainty status if present
        gcp_status = f.get("gcp_details", {}).get("access_evaluation_status", {}).get("overall_status", "DEFINITIVE")
        print(f"[{provider.upper()}] {name} - Public Read: {pub_read} (Status: {gcp_status})")
```

---

## 5. Remediation Playbooks for Person 4 (Dashboard & Reporting)

When generating remediation recommendations in the UI/reports:

1. **If `effective_public_read == True`:**
   - **Recommended Action:** Enable Public Access Prevention (`enforced`) or remove public IAM bindings (`allUsers`, `allAuthenticatedUsers`).
   - **gcloud command:** `gcloud storage buckets update gs://<BUCKET_NAME> --public-access-prevention`
2. **If `gcp_details.uniform_bucket_level_access == False`:**
   - **Recommended Action:** Enable Uniform Bucket-Level Access to eliminate legacy object-level ACL vulnerabilities.
   - **gcloud command:** `gcloud storage buckets update gs://<BUCKET_NAME> --uniform-bucket-level-access`
3. **If `logging_enabled == False`:**
   - **Recommended Action:** Configure a designated access log bucket.
4. **If `versioning_enabled == False`:**
   - **Recommended Action:** Enable versioning for ransomware and accidental deletion defense.

