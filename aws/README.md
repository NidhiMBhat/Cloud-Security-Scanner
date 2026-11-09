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