terraform {
  backend "s3" {
    profile = "codequest-admin"
    region  = "us-west-2"
  }
}