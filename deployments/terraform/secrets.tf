data "aws_secretsmanager_secret" "create_token" {
  provider = aws.lambda
  name     = "quickshort/CreateToken"
}

data "aws_secretsmanager_secret_version" "create_token" {
  provider  = aws.lambda
  secret_id = data.aws_secretsmanager_secret.create_token.id
}

data "aws_secretsmanager_secret" "gh_id" {
  provider = aws.lambda
  name     = "quickshort/GhClientId"
}

data "aws_secretsmanager_secret_version" "gh_id" {
  provider  = aws.lambda
  secret_id = data.aws_secretsmanager_secret.gh_id.id
}

data "aws_secretsmanager_secret" "gh_secret" {
  provider = aws.lambda
  name     = "quickshort/GhClientSecret"
}

data "aws_secretsmanager_secret_version" "gh_secret" {
  provider  = aws.lambda
  secret_id = data.aws_secretsmanager_secret.gh_secret.id
}

data "aws_secretsmanager_secret" "gh_allow" {
  provider = aws.lambda
  name     = "quickshort/AdminGithubAllowlist"
}

data "aws_secretsmanager_secret_version" "gh_allow" {
  provider  = aws.lambda
  secret_id = data.aws_secretsmanager_secret.gh_allow.id
}

data "aws_secretsmanager_secret" "state_key" {
  provider = aws.lambda
  name     = "quickshort/AdminStateKey"
}

data "aws_secretsmanager_secret_version" "state_key" {
  provider  = aws.lambda
  secret_id = data.aws_secretsmanager_secret.state_key.id
}
