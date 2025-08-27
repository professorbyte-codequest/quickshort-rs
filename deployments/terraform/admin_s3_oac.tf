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

# Upload Admin UI (kept in repo under deployments/terraform/admin/index.html)
resource "aws_s3_object" "admin_index" {
  bucket       = aws_s3_bucket.admin.id
  key          = "admin/index.html"
  content_type = "text/html; charset=utf-8"
  content      = file("${path.module}/admin/index.html")
  etag         = filemd5("${path.module}/admin/index.html")
}
