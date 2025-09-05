locals {
  admin_bucket_name = "quickshort-admin-${var.domain_name}"
}

resource "aws_s3_bucket" "admin" {
  bucket        = local.admin_bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "admin" {
  bucket = aws_s3_bucket.admin.id
  rule { object_ownership = "BucketOwnerPreferred" }
}

resource "aws_s3_bucket_public_access_block" "admin" {
  bucket                  = aws_s3_bucket.admin.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Upload Admin UI
resource "aws_s3_object" "admin_index" {
  bucket       = aws_s3_bucket.admin.id
  key          = "admin/index.html"
  content_type = "text/html; charset=utf-8"
  content      = file("${path.module}/admin/index.html")
  etag         = filemd5("${path.module}/admin/index.html")
}

# Upload Auth UI
resource "aws_s3_object" "auth_callback" {
  bucket       = aws_s3_bucket.admin.id
  key          = "auth/callback"
  content_type = "text/html; charset=utf-8"
  content      = file("${path.module}/auth/callback.html")
  etag         = filemd5("${path.module}/auth/callback.html")
}

resource "aws_s3_object" "auth_register" {
  bucket       = aws_s3_bucket.admin.id
  key          = "auth/register"
  content_type = "text/html; charset=utf-8"
  content      = file("${path.module}/auth/register.html")
  etag         = filemd5("${path.module}/auth/register.html")
}

resource "aws_s3_object" "auth_signin" {
  bucket       = aws_s3_bucket.admin.id
  key          = "auth/signin"
  content_type = "text/html; charset=utf-8"
  content      = file("${path.module}/auth/signin.html")
  etag         = filemd5("${path.module}/auth/signin.html")
}

resource "aws_s3_object" "auth_signout" {
  bucket       = aws_s3_bucket.admin.id
  key          = "auth/signout"
  content_type = "text/html; charset=utf-8"
  content      = file("${path.module}/auth/signout.html")
  etag         = filemd5("${path.module}/auth/signout.html")
}

resource "aws_s3_object" "auth_signedout" {
  bucket       = aws_s3_bucket.admin.id
  key          = "auth/signedout"
  content_type = "text/html; charset=utf-8"
  content      = file("${path.module}/auth/signedout.html")
  etag         = filemd5("${path.module}/auth/signedout.html")
}

resource "aws_s3_object" "auth_auth" {
  bucket       = aws_s3_bucket.admin.id
  key          = "auth/auth.js"
  content_type = "text/javascript; charset=utf-8"
  content      = file("${path.module}/auth/auth.js")
  etag         = filemd5("${path.module}/auth/auth.js")
}