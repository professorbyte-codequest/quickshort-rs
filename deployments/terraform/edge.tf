# Render and publish the Edge verifier in us-east-1, then associate with admin/* behavior
locals {
  jwt_public_pem = trimspace(replace(replace(data.aws_kms_public_key.jwt.public_key_pem, "\r", ""), "\n", "\n"))
  edge_js = templatefile("${path.module}/edge/admin_jwt_verify.js.tmpl", {
    # Substitute with care; multi-line PEM gets inlined between backticks
    # We replace placeholders after templatefile call for safety
  })
  edge_js_filled = replace(replace(replace(local.edge_js, "@@PUBLIC_KEY_PEM@@", local.jwt_public_pem), "@@AUD@@", "qs-admin"), "@@ISS@@", "https://${local.fqdn}")
}

data "archive_file" "edge_verify_zip" {
  type        = "zip"
  output_path = "${path.module}/edge/admin_jwt_verify.zip"
  source {
    content  = local.edge_js_filled
    filename = "index.js"
  }
}

resource "aws_iam_role" "edge_verify_role" {
  provider           = aws.use1
  name               = "qs-edge-verify-role"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"] }, Action = "sts:AssumeRole" }] })
}

resource "aws_iam_role_policy_attachment" "edge_verify_basic" {
  provider   = aws.use1
  role       = aws_iam_role.edge_verify_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "edge_verify" {
  provider      = aws.use1
  function_name = "qs-edge-admin-jwt-verify"
  role          = aws_iam_role.edge_verify_role.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = data.archive_file.edge_verify_zip.output_path
  publish       = true
  memory_size   = 128
  timeout       = 1
}

data "archive_file" "edge_root_rewrite_zip" {
  type        = "zip"
  output_path = "${path.module}/edge/edge_root_rewrite.zip"
  source_file = "${path.module}/edge/origin_rewrite_index/index.js"
}

resource "aws_lambda_function" "edge_root_rewrite" {
  provider      = aws.use1
  function_name = "qs-edge-root-rewrite"
  role          = aws_iam_role.edge_root_rewrite_role.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  publish       = true
  timeout       = 3
  filename      = data.archive_file.edge_root_rewrite_zip.output_path
}

# Role for Edge Lambda
resource "aws_iam_role" "edge_root_rewrite_role" {
  name = "qs-edge-root-rewrite-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"] },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "edge_root_rewrite_basic" {
  role       = aws_iam_role.edge_root_rewrite_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}