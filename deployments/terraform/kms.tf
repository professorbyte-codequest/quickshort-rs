resource "aws_kms_key" "jwt" {
  description = "QuickShort Admin JWT signing"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
}

resource "aws_kms_alias" "jwt" {
  name          = "alias/quickshort-jwt"
  target_key_id = aws_kms_key.jwt.key_id
}

data "aws_kms_public_key" "jwt" {
  key_id = aws_kms_key.jwt.key_id
}

resource "aws_iam_policy" "kms_sign" {
  name = "quickshort-kms-sign-jwt"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect : "Allow",
      Action : ["kms:Sign", "kms:Verify"],
      Resource : aws_kms_key.jwt.arn
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_kms_sign" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.kms_sign.arn
}
