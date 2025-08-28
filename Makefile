TERRAFORM_DIR = deployments/terraform

TF_VARS = -var domain_name="codequesthub.io" \
          -var subdomain="go" \
          -var aws_region_lambda="us-west-2"

.PHONY: test tf-plan test-all deploy fmt tf-fmt fmt-all build clean

# Run all tests with all features
test:
	cargo test --all --all-features

# Validate and plan Terraform changes
tf-plan:
	cd $(TERRAFORM_DIR) && terraform init && terraform validate && terraform plan $(TF_VARS)

# Run all tests and validate/plan Terraform changes
test-all: test tf-plan

# Format all Rust code
fmt:
	cargo fmt --all

# Format all Terraform code
tf-fmt:
	cd $(TERRAFORM_DIR) && terraform fmt -recursive

# Format all code
fmt-all: fmt tf-fmt

# Build the Lambda function for deployment
build:
	cargo lambda build --release --arm64 --output-format zip

# Deploy infrastructure and Lambda function
deploy: build
	cd $(TERRAFORM_DIR) && terraform init && terraform apply $(TF_VARS) -auto-approve

# Clean up build artifacts
clean:
	cargo clean