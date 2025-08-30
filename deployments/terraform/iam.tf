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
