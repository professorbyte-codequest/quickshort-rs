locals {
  origin_domain = replace(aws_apigatewayv2_api.http.api_endpoint, "https://", "")
}

data "aws_cloudfront_cache_policy" "caching_optimized" { name = "Managed-CachingOptimized" }

data "aws_cloudfront_cache_policy" "caching_disabled" { name = "Managed-CachingDisabled" }

data "aws_cloudfront_origin_request_policy" "all_viewer" { name = "Managed-AllViewer" }

# Managed policy that forwards all viewer headers EXCEPT Host (includes Authorization)
data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

# cloudfront.tf
resource "aws_cloudfront_origin_request_policy" "minimal" {
  name = "qs-minimal-no-headers-cookies-query"

  headers_config {
    header_behavior = "none"
  }

  cookies_config {
    cookie_behavior = "none"
  }

  query_strings_config {
    query_string_behavior = "none"
  }
}

resource "aws_cloudfront_distribution" "cdn" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "QuickShort for ${local.fqdn}"

  aliases = [local.fqdn]

  origin {
    domain_name = local.origin_domain
    origin_id   = "api-gw-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "api-gw-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_optimized.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.minimal.id
    compress                 = true
  }

  ordered_cache_behavior {
    path_pattern           = "v1/*"
    target_origin_id       = "api-gw-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.cf_cert_validation.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  # Attach WAF (defined below)
  web_acl_id = aws_wafv2_web_acl.cf_acl.arn
}
