# Cloud Security Scanner — AWS Module (Person 1)

This module discovers AWS S3 storage buckets, collects their security configurations, evaluates effective public access across multiple layers, and produces normalized JSON data for the Security Analysis Engine.

---

## 🛠️ What Has Been Built & Completed
- **Automated S3 Discovery:** Connects securely via `boto3` using read-only IAM credentials to list all accessible S3 buckets.
- **Granular Security Auditing:** Automatically fetches and inspects:
  - Default Server-Side Encryption (`get_bucket_encryption`)
  - Server Access Logging (`get_bucket_logging`)
  - Bucket Versioning (`get_bucket_versioning`)
  - Bucket-Level Block Public Access (`get_public_access_block`)
  - Account-Level Block Public Access settings (overrides bucket settings)
  - Bucket Policies & ACLs (detects wildcard principals `*` and public groups like `AllUsers`)
- **Effective Access Calculation:** Resolves whether a bucket is genuinely exposed to public read/write by factoring in AWS Block Public Access guardrails.
- **Infrastructure as Code (Terraform):** Fully automated test environment provisioning (`terraform/`) for compliant and leaky test buckets.
- **Offline Unit Testing:** Comprehensive mock test suite (`aws/test_scanner.py`) using `unittest.mock` to validate security checks without requiring active AWS connectivity.
- **Dynamic Integration Contract:** Exposes a clean Python function (`scan_aws_s3_buckets()`) that feeds normalized JSON data directly into the Analysis Engine in-memory.

---

## ⚙️ Setup & Installation Guide

### 1. Prerequisites
- Python 3.10+ installed
- AWS CLI installed
- Terraform installed (for infrastructure provisioning)

### 2. Configure Local AWS Credentials
Set up your programmatic access keys using a read-only IAM user:
```powershell
aws configure
(Provide your AWS Access Key ID, Secret Access Key, preferred region e.g. ap-south-1, and output format json).

3. Install Dependencies
Navigate to the root directory and install the required Python packages:

PowerShell
pip install -r aws/requirements.txt
🚀 How to Run
Option A: Provision Test Infrastructure via Terraform
To spin up sample secure and misconfigured test buckets automatically:

PowerShell
cd terraform
terraform init
terraform apply
cd ..
Option B: Run the AWS Scanner Module
Execute the scanner to audit your S3 buckets and generate the normalized JSON output:

PowerShell
python aws/aws_scanner.py
Option C: Run Offline Unit Tests
To verify all security checking logic using mock responses:

PowerShell
python -m unittest aws/test_scanner.py
🔌 Integration with Analysis Engine (Person 3)
The Analysis Engine can import and consume live scan results directly in-memory without needing intermediate static files:

Python
from aws.aws_scanner import scan_aws_s3_buckets

# Fetch live normalized security findings
aws_findings = scan_aws_s3_buckets()