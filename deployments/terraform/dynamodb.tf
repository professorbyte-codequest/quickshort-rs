resource "aws_dynamodb_table" "links" {
  provider     = aws.lambda
  name         = "quickshort_links"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "slug"

  attribute {
    name = "slug"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}
