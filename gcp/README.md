# Cloud Security Scanner — GCP Module (Person 2)

This module discovers Google Cloud Storage (GCS) buckets, audits their security configurations across multiple layers, evaluates effective public access (differentiating definitive, conditional, and inconclusive states), and normalizes findings into the shared multi-cloud contract for downstream consumption by Person 3 (Analysis Engine) and Person 4 (API/Dashboard).

---

## 🛠️ What Has Been Built & Completed

- **Automated GCS Discovery:** Connects securely using Application Default Credentials (ADC) or explicit project IDs, with pagination and robust permission handling (`storage.buckets.list`).
- **Granular Security Auditing:** Automatically inspects:
  - **Public Access Prevention (PAP):** Evaluates `enforced`, `inherited`, and `unspecified` states.
  - **Uniform Bucket-Level Access (UBLA):** Verifies whether legacy ACLs are disabled or active.
  - **Cloud IAM Policies (Version 3):** Analyzes `allUsers` and `allAuthenticatedUsers` bindings, distinguishing read (`roles/storage.objectViewer`, etc.) from write (`roles/storage.objectCreator`, etc.).
  - **IAM Condition Expressions:** Detects conditional public grants (`request.time`, etc.) and avoids false-positive binary claims.
  - **Legacy Bucket & Object ACLs:** Evaluates legacy ACL grants only when UBLA is disabled.
  - **Encryption Configuration:** Distinguishes default Google-managed encryption (AES-256 at rest) from Customer-Managed Encryption Keys (CMEK via Cloud KMS).
  - **Usage Logging:** Checks bucket logging target configuration (`log_bucket`).
  - **Object Versioning:** Checks whether versioning is enabled.
- **Accurate Effective Access & Certainty Evaluation:**
  - Factored into GCP infrastructure guardrails: Enforced PAP overrides all public IAM and ACL grants.
  - Inconclusive states (`INCONCLUSIVE_INHERITED_PAP`, `INCONCLUSIVE_LEGACY_ACLS`, `INCONCLUSIVE_IAM_PERMISSION_DENIED`, `INCONCLUSIVE_CUSTOM_ROLE`) are explicitly tracked in machine-readable metadata (`gcp_details.access_evaluation_status`).
- **Offline Unit Testing:** 20 comprehensive unit tests (`gcp/test_gcp_scanner.py`) covering all baseline, edge-case, and SDK regression scenarios without requiring live GCP credentials.
- **Infrastructure as Code (Terraform):** Isolated GCP environment (`terraform/gcp/`) provisioning compliant and misconfigured test buckets.
- **Contract Parity:** Produces output records strictly compatible with Person 1's AWS contract for seamless integration with Person 3's engine.

---

## ⚙️ Setup & Installation Guide

### 1. Prerequisites
- Python 3.10+ installed
- Google Cloud CLI (`gcloud`) installed (for live scans)
- Terraform 1.0+ installed (for infrastructure provisioning)

### 2. Configure Local GCP Authentication
To authenticate locally without hardcoding credentials:
```bash
gcloud auth application-default login
gcloud config set project <YOUR_PROJECT_ID>
```

### 3. Required Minimum IAM Permissions
For read-only security auditing, the service account or identity requires:
- `storage.buckets.list` (Discovers buckets in the project)
- `storage.buckets.get` (Inspects bucket settings, PAP, UBLA, versioning, logging)
- `storage.buckets.getIamPolicy` (Inspects bucket IAM bindings)

Predefined roles that grant these permissions:
- `roles/storage.viewer` (Basic read-only inspection)
- `roles/storage.insightsCollectorService` (Security auditing)

### 4. Install Dependencies
```bash
pip install -r gcp/requirements.txt
```

---

## 🚀 How to Run

### Option A: Run Offline Unit Tests
Run the complete mock test suite without needing live GCP credentials or cloud connectivity:
```bash
python -m unittest gcp/test_gcp_scanner.py
# or directly:
python gcp/test_gcp_scanner.py
```

### Option B: Run the GCP Scanner Module Live
Execute the scanner against your active GCP project to produce normalized JSON output:
```bash
# Recommended module invocation (from repository root):
python -m gcp.gcp_scanner [OPTIONAL_PROJECT_ID]

# Or package invocation:
python -m gcp [OPTIONAL_PROJECT_ID]

# Or direct script invocation:
python gcp/gcp_scanner.py [OPTIONAL_PROJECT_ID]
```

### Option C: Provision Test Infrastructure via Terraform
To spin up sample compliant and misconfigured buckets in a sandbox project:
```bash
cd terraform/gcp
terraform init
terraform plan -var="project_id=<YOUR_PROJECT_ID>"
terraform apply -var="project_id=<YOUR_PROJECT_ID>"
cd ../..
```
*(Always run `terraform destroy` when testing is complete to clean up).*

---

## 🔌 Integration with Analysis Engine (Person 3)

The Analysis Engine imports and consumes normalized GCP scan findings in-memory:

```python
from gcp.gcp_scanner import scan_gcp_storage_buckets

# Fetch live normalized security findings
gcp_findings = scan_gcp_storage_buckets(project_id="my-gcp-project")

for record in gcp_findings:
    print(f"Bucket: {record['bucket_name']}")
    print(f"  Public Read: {record['effective_public_read']}")
    print(f"  Certainty:   {record['gcp_details']['access_evaluation_status']['read_status']}")
```

