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
      CACHE_MAX_AGE        = 86400
      PUBLIC_DOMAIN        = local.fqdn
      CREATE_TOKEN         = nonsensitive(data.aws_secretsmanager_secret_version.create_token.secret_string)
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
