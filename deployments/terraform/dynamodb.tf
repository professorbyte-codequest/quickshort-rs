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

  attribute {
    name = "owner_id"
    type = "S"
  }

  global_secondary_index {
    name            = "GSI1-owner"
    hash_key        = "owner_id" # partition key
    range_key       = "slug"     # sort by slug (optional but handy)
    projection_type = "ALL"
  }

}

resource "aws_dynamodb_table" "usage" {
  provider     = aws.lambda
  name         = "quickshort_usage"
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "pk"
  range_key = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  point_in_time_recovery { enabled = true }
}