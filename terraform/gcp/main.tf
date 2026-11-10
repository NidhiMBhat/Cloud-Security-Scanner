terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "random_id" "suffix" {
  byte_length = 4
}

# ------------------------------------------------------------------------------
# 1. Audit Log Sink Bucket (for logging target)
# ------------------------------------------------------------------------------
resource "google_storage_bucket" "audit_logs" {
  name                        = "${var.bucket_prefix}-logs-${random_id.suffix.hex}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  versioning {
    enabled = true
  }
}

# ------------------------------------------------------------------------------
# 2. Secure Production Bucket (Compliant Baseline)
#    - Uniform Bucket-Level Access (UBLA) Enabled
#    - Public Access Prevention (PAP) Enforced
#    - Versioning Enabled
#    - Access Logging Configured
#    - Default Google-Managed Encryption (AES-256)
# ------------------------------------------------------------------------------
resource "google_storage_bucket" "secure_bucket" {
  name                        = "${var.bucket_prefix}-secure-prod-${random_id.suffix.hex}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  versioning {
    enabled = true
  }

  logging {
    log_bucket        = google_storage_bucket.audit_logs.name
    log_object_prefix = "secure-bucket-logs/"
  }
}

# ------------------------------------------------------------------------------
# 3. Misconfigured Leaky Bucket (Controlled Public Read Exposure)
#    - Public Access Prevention Inherited (Unenforced at bucket level)
#    - Uniform Bucket-Level Access Enabled
#    - Versioning Disabled
#    - Access Logging Disabled
#    - Public Read Granted to allUsers via roles/storage.objectViewer
#    - SAFEGUARD: NEVER grant public write (roles/storage.objectCreator or Admin)
# ------------------------------------------------------------------------------
resource "google_storage_bucket" "leaky_read_bucket" {
  name                        = "${var.bucket_prefix}-leaky-read-${random_id.suffix.hex}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "inherited"
  force_destroy               = true

  versioning {
    enabled = false
  }
}

resource "google_storage_bucket_iam_member" "public_read_binding" {
  bucket = google_storage_bucket.leaky_read_bucket.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

