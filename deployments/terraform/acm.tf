# Certificate in us-east-1 for CloudFront
data "aws_acm_certificate" "cf_cert" {
  provider    = aws.use1
  domain      = "${var.subdomain}.${var.domain_name}"
  most_recent = true
  statuses    = ["ISSUED"]
}

#resource "aws_route53_record" "cf_cert_validation" {
#  for_each = {
#    for dvo in aws_acm_certificate.cf_cert.domain_validation_options : dvo.domain_name => {
#      name  = dvo.resource_record_name
#      type  = dvo.resource_record_type
#      value = dvo.resource_record_value
#    }
#  }
#  zone_id = data.aws_route53_zone.zone.zone_id
#  name    = each.value.name
#  type    = each.value.type
#  ttl     = 60
#  records = [each.value.value]
#}

#resource "aws_acm_certificate_validation" "cf_cert_validation" {
#  provider                = aws.use1
#  certificate_arn         = aws_acm_certificate.cf_cert.arn
#  validation_record_fqdns = [for r in aws_route53_record.cf_cert_validation : r.fqdn]
#}
