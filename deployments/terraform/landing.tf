# S3 bucket for landing page (private, OAC only)
resource "aws_s3_bucket" "landing" {
  bucket        = "quickshort-landing-${var.domain_name}"
  force_destroy = false
  tags          = { app = "quickshort", role = "landing" }
}

resource "aws_s3_bucket_ownership_controls" "landing" {
  bucket = aws_s3_bucket.landing.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "landing" {
  bucket                  = aws_s3_bucket.landing.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Origin Access Control for the landing bucket (us-east-1 for CF)
resource "aws_cloudfront_origin_access_control" "landing" {
  provider                          = aws.use1
  name                              = "qs-landing-oac"
  description                       = "OAC for landing bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Bucket policy to allow only the distribution (via OAC) to read
# Injects the distribution ID after it's created/known.
data "aws_iam_policy_document" "landing_bucket_policy" {
  statement {
    sid    = "AllowCloudFrontOAC"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    actions = ["s3:GetObject"]
    resources = [
      "${aws_s3_bucket.landing.arn}/*"
    ]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = ["arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:distribution/${aws_cloudfront_distribution.cdn.id}"]
    }
  }
}


data "aws_caller_identity" "current" {}


resource "aws_s3_bucket_policy" "landing" {
  bucket = aws_s3_bucket.landing.id
  policy = data.aws_iam_policy_document.landing_bucket_policy.json
}


# Upload index.html (alternatively, use file() to read from repo)
resource "aws_s3_object" "landing_index" {
  bucket        = aws_s3_bucket.landing.id
  key           = "index.html"
  content_type  = "text/html; charset=utf-8"
  content       = file("${path.module}/site/index.html")
  etag          = filemd5("${path.module}/site/index.html")
  cache_control = "public, max-age=300"
}


# Upload index.html (alternatively, use file() to read from repo)
resource "aws_s3_object" "users_index" {
  bucket        = aws_s3_bucket.landing.id
  key           = "users/index.html"
  content_type  = "text/html; charset=utf-8"
  content       = file("${path.module}/site/users/index.html")
  etag          = filemd5("${path.module}/site/users/index.html")
  cache_control = "public, max-age=300"
}