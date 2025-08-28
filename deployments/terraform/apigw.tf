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
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "POST /v1/links"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "resolve" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "GET /{slug}"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "list" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "GET /v1/links"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "delete" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "DELETE /v1/links/{slug}"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
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
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "GET /v1/admin/me"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

output "api_invoke_url" { value = aws_apigatewayv2_api.http.api_endpoint }

