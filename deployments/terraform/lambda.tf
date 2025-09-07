# Path to cargo-lambda artifact
locals { lambda_zip = "${path.module}/../../target/lambda/quickshort/bootstrap.zip" }

resource "aws_lambda_function" "api" {
  provider         = aws.lambda
  function_name    = "quickshort_api"
  role             = aws_iam_role.lambda_role.arn
  filename         = local.lambda_zip
  source_code_hash = filebase64sha256(local.lambda_zip)
  handler          = "bootstrap"
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  timeout          = 5
  memory_size      = 512
  environment {
    variables = {
      TABLE_NAME           = aws_dynamodb_table.links.name
      TABLE_USERS          = aws_dynamodb_table.users.name
      TABLE_USAGE                 = aws_dynamodb_table.usage.name
      FREE_MONTHLY_LINKS          = "50"
      FREE_TOTAL_LINKS            = "200"
      FREE_BUCKET_CAPACITY        = "10"
      FREE_BUCKET_REFILL_PER_SEC  = "0.5"  # 1 token every 2s
      CACHE_MAX_AGE        = 86400
      PUBLIC_DOMAIN        = local.fqdn
      GITHUB_CLIENT_ID     = nonsensitive(data.aws_secretsmanager_secret_version.gh_id.secret_string)
      GITHUB_CLIENT_SECRET = nonsensitive(data.aws_secretsmanager_secret_version.gh_secret.secret_string)
      ADMIN_GITHUB_LOGINS  = nonsensitive(data.aws_secretsmanager_secret_version.gh_allow.secret_string)
      ADMIN_STATE_KEY      = nonsensitive(data.aws_secretsmanager_secret_version.state_key.secret_string)
      JWT_AUD              = "qs-admin"
      JWT_ISS              = "https://${local.fqdn}"
      JWT_TTL              = "3600"
      JWT_KMS_KEY_ID       = aws_kms_key.jwt.key_id
    }
  }
}

resource "aws_iam_role" "logproc_role" {
  name = "qs-logproc-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "logproc_policy" {
  name = "qs-logproc-ddb-kinesis"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "kinesis:DescribeStream",
          "kinesis:GetShardIterator",
          "kinesis:GetRecords",
          "kinesis:ListShards"
        ],
        Resource = aws_kinesis_stream.cf_rt_logs.arn
      },
      {
        Effect   = "Allow",
        Action   = ["dynamodb:UpdateItem", "dynamodb:DescribeTable"],
        Resource = aws_dynamodb_table.links.arn
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "logproc_attach" {
  role       = aws_iam_role.logproc_role.name
  policy_arn = aws_iam_policy.logproc_policy.arn
}

# Path to the built zip produced by `cargo lambda build --arm64 --output-format zip`
# Expecting it at ../../target/lambda/logproc/bootstrap.zip from this tf dir
locals {
  logproc_zip    = "../../target/lambda/logproc/bootstrap.zip"
  authorizer_zip = "../../target/lambda/qs_authorizer/bootstrap.zip"
}

resource "aws_lambda_function" "logproc" {
  provider         = aws.use1
  function_name    = "quickshort_cf_logproc"
  filename         = local.logproc_zip
  source_code_hash = filebase64sha256(local.logproc_zip)
  handler          = "bootstrap"
  role             = aws_iam_role.logproc_role.arn
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      TABLE_NAME   = aws_dynamodb_table.links.name
      TABLE_REGION = var.aws_region_lambda # us-west-2 (write to DDB in west-2)
      LOG_LEVEL    = "info"
    }
  }
}

resource "aws_lambda_function" "authorizer" {
  provider         = aws.lambda
  function_name    = "quickshort_authorizer"
  role             = aws_iam_role.lambda_role.arn
  filename         = local.authorizer_zip
  source_code_hash = filebase64sha256(local.authorizer_zip)
  handler          = "bootstrap"
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  timeout          = 5
  memory_size      = 256

  environment {
    variables = {
      COGNITO_ISS          = "https://cognito-idp.${var.aws_region_lambda}.amazonaws.com/${aws_cognito_user_pool.qs.id}"
      COGNITO_CLIENT_ID    = aws_cognito_user_pool_client.app.id
      GITHUB_CLIENT_ID     = nonsensitive(data.aws_secretsmanager_secret_version.gh_id.secret_string)
      GITHUB_CLIENT_SECRET = nonsensitive(data.aws_secretsmanager_secret_version.gh_secret.secret_string)
      ADMIN_GITHUB_LOGINS  = nonsensitive(data.aws_secretsmanager_secret_version.gh_allow.secret_string)
      ADMIN_STATE_KEY      = nonsensitive(data.aws_secretsmanager_secret_version.state_key.secret_string)
      JWT_AUD              = "qs-admin"
      JWT_ISS              = "https://${local.fqdn}"
      TABLE_USERS          = aws_dynamodb_table.users.name
    }
  }
}


resource "aws_lambda_event_source_mapping" "kinesis_to_logproc" {
  provider                           = aws.use1
  event_source_arn                   = aws_kinesis_stream.cf_rt_logs.arn
  function_name                      = aws_lambda_function.logproc.arn
  starting_position                  = "LATEST"
  batch_size                         = 100
  maximum_batching_window_in_seconds = 5
  bisect_batch_on_function_error     = true
  maximum_retry_attempts             = 3
  parallelization_factor             = 1
}
