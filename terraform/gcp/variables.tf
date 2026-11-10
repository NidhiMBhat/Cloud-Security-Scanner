variable "project_id" {
  description = "The GCP Project ID where test storage buckets will be provisioned."
  type        = string
}

variable "region" {
  description = "The GCP region for the storage buckets."
  type        = string
  default     = "us-central1"
}

variable "bucket_prefix" {
  description = "Prefix prepended to bucket names for isolation and uniqueness."
  type        = string
  default     = "sec-audit-gcp"
}

