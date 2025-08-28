output "ddb_table" { value = aws_dynamodb_table.links.name }

output "cf_distribution_id" {
  description = "CloudFront distribution ID"
  value       = aws_cloudfront_distribution.cdn.id
}
