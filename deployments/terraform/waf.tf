# ===== deployments/terraform/waf.tf (NEW) =====
resource "aws_wafv2_web_acl" "cf_acl" {
  provider    = aws.use1
  name        = "quickshort-cf-acl"
  description = "Rate limit POST to /v1 via CloudFront"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "rate-limit-v1"
    priority = 1
    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 200 # requests per 5 minutes per IP
        aggregate_key_type = "IP"
        scope_down_statement {
          byte_match_statement {
            search_string = "/v1/"
            field_to_match {
              uri_path {}
            }
            positional_constraint = "STARTS_WITH"
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit-v1"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "quickshort-cf-acl"
    sampled_requests_enabled   = true
  }
}