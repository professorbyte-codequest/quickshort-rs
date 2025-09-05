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

resource "aws_cloudfront_response_headers_policy" "security" {
  provider = aws.use1
  name     = "qs-security-hsts"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000 # 1 year
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    content_type_options { override = true }
    frame_options {
      frame_option = "SAMEORIGIN"
      override     = true
    }
    referrer_policy {
      referrer_policy = "no-referrer-when-downgrade"
      override        = true
    }
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
  }
}

resource "aws_cloudfront_response_headers_policy" "api_cors" {
  provider = aws.use1
  name     = "qs-api-cors"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000 # 1 year
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    content_type_options { override = true }
    frame_options {
      frame_option = "SAMEORIGIN"
      override     = true
    }
    referrer_policy {
      referrer_policy = "no-referrer-when-downgrade"
      override        = true
    }
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
  }

  cors_config {
    access_control_allow_credentials = false
    access_control_allow_headers {
      items = ["Authorization", "Content-Type"]
    }
    access_control_allow_methods {
      items = ["GET", "POST", "DELETE", "OPTIONS"]
    }
    access_control_allow_origins {
      items = ["https://go.${var.domain_name}"]
    }
    access_control_expose_headers { items = [] }
    access_control_max_age_sec = 600
    origin_override            = true
  }
}

resource "aws_cloudfront_origin_access_control" "oac" {
  provider                          = aws.use1
  name                              = "qs-oac-s3"
  description                       = "OAC for S3 origins (admin)"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_function" "notfound_redirect" {
  provider = aws.use1
  name     = "qs-notfound-redirect"
  runtime  = "cloudfront-js-1.0"
  comment  = "Redirect 404s on default path to site"
  publish  = true
  code     = file("${path.module}/cf-functions/notfound_redirect.js")
}

resource "aws_cloudfront_realtime_log_config" "redirects" {
  provider      = aws.use1
  name          = "qs-redirects-rt-json"
  sampling_rate = 100


  fields = [
    # minimal set for our needs; extend later if you want UA/region stats
    "timestamp", # epoch millis
    "cs-host",
    "cs-uri-stem",
    "sc-status",
    "x-edge-result-type"
  ]


  endpoint {
    stream_type = "Kinesis"
    kinesis_stream_config {
      role_arn   = aws_iam_role.cf_logs_role.arn
      stream_arn = aws_kinesis_stream.cf_rt_logs.arn
    }
  }
}

resource "aws_cloudfront_distribution" "cdn" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "QuickShort for ${local.fqdn}"
  http_version    = "http2and3"

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

  origin {
    domain_name              = aws_s3_bucket.admin.bucket_regional_domain_name
    origin_id                = "admin-s3-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }

  origin {
    domain_name              = aws_s3_bucket.landing.bucket_regional_domain_name
    origin_id                = "landing-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.landing.id
  }

  default_cache_behavior {
    target_origin_id       = "api-gw-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_optimized.id
    origin_request_policy_id   = aws_cloudfront_origin_request_policy.minimal.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id
    compress                   = true

    function_association {
      event_type   = "viewer-response"
      function_arn = aws_cloudfront_function.notfound_redirect.arn
    }

    realtime_log_config_arn = aws_cloudfront_realtime_log_config.redirects.arn
  }

  ordered_cache_behavior {
    path_pattern     = "/"
    target_origin_id = "landing-s3"

    allowed_methods = ["GET", "HEAD"]
    cached_methods  = ["GET", "HEAD"]

    viewer_protocol_policy = "redirect-to-https"

    # Cache aggressively; it's static
    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_optimized.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id

    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = aws_lambda_function.edge_root_rewrite.qualified_arn
      include_body = false
    }
  }

  ordered_cache_behavior {
    path_pattern           = "v1/*"
    target_origin_id       = "api-gw-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.api_cors.id
  }

  ordered_cache_behavior {
    path_pattern           = "admin/*"
    target_origin_id       = "admin-s3-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_optimized.id
    origin_request_policy_id   = aws_cloudfront_origin_request_policy.minimal.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id
    compress                   = true

    lambda_function_association {
      event_type   = "viewer-request"
      include_body = false
      lambda_arn   = aws_lambda_function.edge_verify.qualified_arn
    }
  }

  ordered_cache_behavior {
    path_pattern           = "users/*"
    target_origin_id       = "landing-s3"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_optimized.id
    origin_request_policy_id   = aws_cloudfront_origin_request_policy.minimal.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id
    compress                   = true

    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = aws_lambda_function.edge_root_rewrite.qualified_arn
      include_body = false
    }
  }

  ordered_cache_behavior {
    path_pattern           = "auth/*"
    target_origin_id       = "admin-s3-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_optimized.id
    origin_request_policy_id   = aws_cloudfront_origin_request_policy.minimal.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id
    compress                   = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = data.aws_acm_certificate.cf_cert.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  # Attach WAF (defined below)
  web_acl_id = aws_wafv2_web_acl.cf_acl.arn
}
