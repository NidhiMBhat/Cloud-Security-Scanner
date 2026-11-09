provider "aws" {
  region = "ap-south-1" # Update to your region
}

# 1. Secure Production Bucket (Compliant)
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "company-secure-prod-nidhi-tf"
}

resource "aws_s3_bucket_public_access_block" "secure_bpa" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# 2. Insecure / Leaky Bucket (Public Policy & Public Access Block OFF)
resource "aws_s3_bucket" "leaky_bucket" {
  bucket        = "company-leaky-archive-nidhi-tf"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "leaky_bpa" {
  bucket                  = aws_s3_bucket.leaky_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "leaky_policy" {
  bucket = aws_s3_bucket.leaky_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.leaky_bucket.arn}/*"
      }
    ]
  })
}