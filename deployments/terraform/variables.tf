variable "domain_name" {
  description = "Base domain, e.g., codequesthub.io"
  type        = string
}

variable "subdomain" {
  description = "Subdomain for short links, e.g., go"
  type        = string
  default     = "go"
}

variable "aws_region_lambda" {
  description = "Region for Lambda/API GW/DynamoDB"
  type        = string
  default     = "us-west-2"
}

locals {
  fqdn = "${var.subdomain}.${var.domain_name}"
}

variable "create_token" {
  description = "Bearer token required for POST /v1/links (empty disables auth)"
  type        = string
  sensitive   = true
  default     = null
}
