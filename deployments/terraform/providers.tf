terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# Default provider (used by data sources like Route53, and any resource without an explicit alias)
provider "aws" {
  region  = var.aws_region_lambda
  profile = "codequest-admin"
}

# Alias for Lambda/API GW/DynamoDB region
provider "aws" {
  alias   = "lambda"
  region  = var.aws_region_lambda
  profile = "codequest-admin"
}

# Alias for us-east-1 (ACM for CloudFront certs, CloudFront itself)
provider "aws" {
  alias   = "use1"
  region  = "us-east-1"
  profile = "codequest-admin"
}
