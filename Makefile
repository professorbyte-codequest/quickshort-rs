build:
	cargo lambda build --release --arm64 --output-format zip

package: build
	@echo "Zip at target/lambda/quickshort/bootstrap.zip"


deploy:
	cd deployments/terraform && terraform init && terraform apply -auto-approve \
	-var domain_name=codequesthub.io -var subdomain=go -var aws_region_lambda=us-west-2
