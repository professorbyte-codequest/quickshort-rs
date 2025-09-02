data "aws_secretsmanager_secret_version" "google_id" { secret_id = "quickshort/GoogleClientId" }
data "aws_secretsmanager_secret_version" "google_secret" { secret_id = "quickshort/GoogleClientSecret" }

#data "aws_secretsmanager_secret_version" "apple_team_id" { secret_id = "quickshort/AppleTeamId" }
#data "aws_secretsmanager_secret_version" "apple_key_id" { secret_id = "quickshort/AppleKeyId" }
#data "aws_secretsmanager_secret_version" "apple_private_key" { secret_id = "quickshort/ApplePrivateKey" }
#data "aws_secretsmanager_secret_version" "apple_service_id" { secret_id = "quickshort/AppleServiceId" }

data "aws_secretsmanager_secret_version" "gh_oidc_client_id" { secret_id = "quickshort/GhClientId" }
data "aws_secretsmanager_secret_version" "gh_oidc_client_secret" { secret_id = "quickshort/GhClientSecret" }


locals {
  cognito_domain = "https://${aws_cognito_user_pool_domain.qs.domain}.auth.${var.aws_region_lambda}.amazoncognito.com"
  client_id      = aws_cognito_user_pool_client.app.id
  redirect_uri   = "https://${var.subdomain}.${var.domain_name}/auth/callback"
  logout_uri     = "https://${var.subdomain}.${var.domain_name}/auth/signedout"
}

resource "aws_cognito_user_pool" "qs" {
  provider                 = aws.lambda
  name                     = "quickshort-users"
  auto_verified_attributes = ["email"]
  schema {
    name                = "email"
    attribute_data_type = "String"
    required            = true
    mutable             = true
  }
  password_policy { minimum_length = 8 }
}

resource "aws_cognito_user_pool_domain" "qs" {
  provider     = aws.lambda
  domain       = "quickshort-auth"
  user_pool_id = aws_cognito_user_pool.qs.id
}

resource "aws_cognito_user_pool_client" "app" {
  provider     = aws.lambda
  name         = "qs-app"
  user_pool_id = aws_cognito_user_pool.qs.id

  callback_urls = [local.redirect_uri]
  logout_urls   = [local.logout_uri]

  supported_identity_providers         = ["COGNITO", "Google"]
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  allowed_oauth_flows_user_pool_client = true
  generate_secret                      = false
}

# Google
resource "aws_cognito_identity_provider" "google" {
  provider      = aws.lambda
  user_pool_id  = aws_cognito_user_pool.qs.id
  provider_name = "Google"
  provider_type = "Google"
  provider_details = {
    client_id        = data.aws_secretsmanager_secret_version.google_id.secret_string
    client_secret    = data.aws_secretsmanager_secret_version.google_secret.secret_string
    authorize_scopes = "openid email profile"
  }
  attribute_mapping = { email = "email" }
}

# Apple
#resource "aws_cognito_identity_provider" "apple" {
#  user_pool_id  = aws_cognito_user_pool.qs.id
#  provider_name = "SignInWithApple"
#  provider_type = "SignInWithApple"
#  provider_details = {
#    client_id        = data.aws_secretsmanager_secret_version.apple_service_id.secret_string
#    team_id          = data.aws_secretsmanager_secret_version.apple_team_id.secret_string
#    key_id           = data.aws_secretsmanager_secret_version.apple_key_id.secret_string
#    private_key      = data.aws_secretsmanager_secret_version.apple_private_key.secret_string
#    authorize_scopes = "name email"
#  }
#}

# GitHub via OIDC
#resource "aws_cognito_identity_provider" "github" {
#  provider = aws.lambda
#  user_pool_id  = aws_cognito_user_pool.qs.id
#  provider_name = "GitHub"
#  provider_type = "OIDC"
#  provider_details = {
#    attributes_request_method = "GET"
#    oidc_issuer               = "https://github.com/login/oauth"
#    authorize_scopes          = "openid user:email"
#    authorize_url             = "https://github.com/login/oauth/authorize"
#    token_url                 = "https://github.com/login/oauth/access_token"
#    attributes_url            = "https://api.github.com/user"
#    client_id                 = data.aws_secretsmanager_secret_version.gh_oidc_client_id.secret_string
#    client_secret             = data.aws_secretsmanager_secret_version.gh_oidc_client_secret.secret_string
#  }
#  attribute_mapping = { email = "email" }
#}

output "cognito_user_pool_id" { value = aws_cognito_user_pool.qs.id }
output "cognito_client_id" { value = aws_cognito_user_pool_client.app.id }
output "cognito_issuer" { value = "https://cognito-idp.${var.aws_region_lambda}.amazonaws.com/${aws_cognito_user_pool.qs.id}" }

data "aws_region" "current" {}


resource "aws_s3_object" "auth_config" {
  bucket       = aws_s3_bucket.admin.id
  key          = "auth/config.js"
  content_type = "application/javascript"
  content      = <<-EOT
    window.QS_AUTH_CONFIG = {
      cognitoDomain: "${local.cognito_domain}",
      clientId: "${local.client_id}",
      redirectUri: "${local.redirect_uri}",
      logoutUri: "${local.logout_uri}",
      scope: "openid email profile",
      identityProvider: "Google",
    };
  EOT
}
