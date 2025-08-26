data "aws_secretsmanager_secret" "create_token" {
  provider = aws.lambda
  name     = "quickshort/CreateToken"
}

data "aws_secretsmanager_secret_version" "create_token" {
  provider  = aws.lambda
  secret_id = data.aws_secretsmanager_secret.create_token.id
}