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

resource "aws_dynamodb_table" "users" {
  name         = "quickshort-users"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "user_id"


  attribute {
    name = "user_id"
    type = "S"
  }
  attribute {
    name = "email"
    type = "S"
  }

  # Optional GSI by email (handy for admin lookups / support)
  global_secondary_index {
    name               = "GSI1-email"
    hash_key           = "email"
    projection_type    = "INCLUDE"
    non_key_attributes = ["user_id", "plan", "created_at"]
  }


  tags = { app = "quickshort" }
}
