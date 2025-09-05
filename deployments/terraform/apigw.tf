# Authorizer

# One authorizer for all /v1/* routes
resource "aws_apigatewayv2_authorizer" "combined" {
  api_id          = aws_apigatewayv2_api.http.id
  name            = "qs-combined-auth"
  authorizer_type = "REQUEST"
  authorizer_uri  = aws_lambda_function.authorizer.invoke_arn
  # HTTP API v2
  authorizer_payload_format_version = "2.0"
  enable_simple_responses           = true

  identity_sources = [
    "$request.header.Authorization",
    "$request.header.cookie"
  ]
}

resource "aws_apigatewayv2_api" "http" {
  provider      = aws.lambda
  name          = "quickshort-http"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.http.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "create" {
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.combined.id
  api_id             = aws_apigatewayv2_api.http.id
  route_key          = "POST /v1/links"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "resolve" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "GET /{slug}"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "list" {
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.combined.id
  api_id             = aws_apigatewayv2_api.http.id
  route_key          = "GET /v1/links"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "delete" {
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.combined.id
  api_id             = aws_apigatewayv2_api.http.id
  route_key          = "DELETE /v1/links/{slug}"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.http.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "allow_apigw" {
  statement_id  = "AllowAPIGwInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}


# Allow API Gateway to invoke the authorizer
resource "aws_lambda_permission" "authz_invoke" {
  statement_id  = "AllowAPIGatewayInvokeAuthz"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorizer.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}

resource "aws_apigatewayv2_route" "oauth_start" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "GET /v1/admin/oauth/start"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "oauth_callback" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "GET /v1/admin/oauth/callback"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "admin_logout" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "POST /v1/admin/logout"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "admin_me" {
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.combined.id
  api_id             = aws_apigatewayv2_api.http.id
  route_key          = "GET /v1/admin/me"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "links_put" {
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.combined.id
  api_id             = aws_apigatewayv2_api.http.id
  route_key          = "PUT /v1/links/{slug}"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}


# POST /v1/users/ensure (protected)
resource "aws_apigatewayv2_route" "users_ensure" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "POST /v1/users/ensure"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"


  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.combined.id
}


# GET /v1/users/me (protected)
resource "aws_apigatewayv2_route" "users_me" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "GET /v1/users/me"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"


  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.combined.id
}

output "api_invoke_url" { value = aws_apigatewayv2_api.http.api_endpoint }