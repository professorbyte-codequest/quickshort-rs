data "aws_route53_zone" "zone" { name = var.domain_name }

resource "aws_route53_record" "short_alias" {
  zone_id = data.aws_route53_zone.zone.zone_id
  name    = local.fqdn
  type    = "A"
  alias {
    name                   = aws_cloudfront_distribution.cdn.domain_name
    zone_id                = aws_cloudfront_distribution.cdn.hosted_zone_id
    evaluate_target_health = false
  }
}

output "fqdn" { value = local.fqdn }

