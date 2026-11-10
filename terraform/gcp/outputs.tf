output "audit_logs_bucket" {
  description = "Name of the access logs sink bucket."
  value       = google_storage_bucket.audit_logs.name
}

output "secure_bucket" {
  description = "Name of the compliant secure GCS bucket."
  value       = google_storage_bucket.secure_bucket.name
}

output "leaky_read_bucket" {
  description = "Name of the misconfigured public-read test bucket."
  value       = google_storage_bucket.leaky_read_bucket.name
}

