TERRAFORM_DIR = deployments/terraform

TF_VARS = -var domain_name="codequesthub.io" \
          -var subdomain="go" \
          -var aws_region_lambda="us-west-2"

.PHONY: test tf-plan test-all deploy fmt tf-fmt fmt-all build clean invalidate-admin invalidate-all invalidate-users build-logproc build-authorizer

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
build: build-logproc build-authorizer
	cargo lambda build --release --arm64 --output-format zip

build-logproc:
	cargo lambda build --release --arm64 --output-format zip --bin logproc

build-authorizer:
	cargo lambda build --release --arm64 --output-format zip --bin qs_authorizer

# Deploy infrastructure and Lambda function
deploy: build
	cd $(TERRAFORM_DIR) terraform init && terraform apply $(TF_VARS) -auto-approve

# Clean up build artifacts
clean:
	cargo clean

invalidate-admin:
	@cd $(TERRAFORM_DIR) && \
	DISTRIBUTION_ID=$$(terraform output -raw cf_distribution_id) && \
	echo "Invalidating /admin/* on $$DISTRIBUTION_ID ..." && \
	aws cloudfront create-invalidation \
	  --distribution-id $$DISTRIBUTION_ID \
	  --paths "/admin" "/admin/" "/admin/index.html" "/admin/*"

invalidate-all:
	@cd $(TERRAFORM_DIR) && \
	DISTRIBUTION_ID=$$(terraform output -raw cf_distribution_id) && \
	echo "Invalidating /* on $$DISTRIBUTION_ID ..." && \
	aws cloudfront create-invalidation \
	  --distribution-id $$DISTRIBUTION_ID \
	  --paths "/*"

invalidate-users:
	@cd $(TERRAFORM_DIR) && \
	DISTRIBUTION_ID=$$(terraform output -raw cf_distribution_id) && \
	echo "Invalidating /users/* on $$DISTRIBUTION_ID ..." && \
	aws cloudfront create-invalidation \
	  --distribution-id $$DISTRIBUTION_ID \
	  --paths "/users" "/users/" "/users/*" "/auth/*"