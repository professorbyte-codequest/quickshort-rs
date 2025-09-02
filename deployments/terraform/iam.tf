resource "aws_iam_role" "lambda_role" {
  name = "quickshort_lambda_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "basic_logs" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "ddb_links_rw" {
  name        = "quickshort-ddb-links-rw"
  description = "Allow Put/Get/Update only on the quickshort_links table"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Scan",
          "dynamodb:DeleteItem"
        ],
        Resource = aws_dynamodb_table.links.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ddb_links_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.ddb_links_rw.arn
}

# Attach to your existing lambda role policy (new statement)
resource "aws_iam_policy" "ddb_access" {
  name = "qs-ddb-links-usage"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = [
        "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query",
        "dynamodb:TransactWriteItems"
      ],
      Resource = [
        aws_dynamodb_table.links.arn,
        "${aws_dynamodb_table.links.arn}/index/*",
        aws_dynamodb_table.usage.arn
      ]
    }]
  })
}
resource "aws_iam_role_policy_attachment" "lambda_ddb_access" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.ddb_access.arn
}

resource "aws_iam_role" "cf_logs_role" {
  name = "qs-cf-rt-logs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "cloudfront.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}


resource "aws_iam_policy" "cf_logs_kinesis_put" {
  name = "qs-cf-rt-logs-kinesis-put"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = [
        "kinesis:PutRecord",
        "kinesis:PutRecords",
        "kinesis:DescribeStream",
        "kinesis:DescribeStreamSummary"
      ],
      Resource = aws_kinesis_stream.cf_rt_logs.arn
    }]
  })
}


resource "aws_iam_role_policy_attachment" "cf_logs_attach" {
  role       = aws_iam_role.cf_logs_role.name
  policy_arn = aws_iam_policy.cf_logs_kinesis_put.arn
}

resource "aws_iam_role" "authorizer_role" {
  name = "quickshort-authorizer-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

# CloudWatch Logs (managed policy)
resource "aws_iam_role_policy_attachment" "authorizer_logs" {
  role       = aws_iam_role.authorizer_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# KMS verify for legacy admin cookie (least privilege)
resource "aws_iam_policy" "authorizer_kms_verify" {
  name = "quickshort-authorizer-kms-verify"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect : "Allow",
      Action : [
        "kms:Verify",
        "kms:DescribeKey" # handy for debugging/alg checks
      ],
      Resource : aws_kms_key.jwt.arn # <-- your existing key used to sign the admin cookie
    }]
  })
}

resource "aws_iam_role_policy_attachment" "authorizer_kms_attach" {
  role       = aws_iam_role.authorizer_role.name
  policy_arn = aws_iam_policy.authorizer_kms_verify.arn
}