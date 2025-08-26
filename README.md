# QuickShort‑RS

A small‑but‑serious Rust URL shortener designed for AWS Lambda + API Gateway + DynamoDB, fronted by CloudFront on `go.codequesthub.io`.

## Architecture
- **Client:** your blog / CLI / curl
- **Edge:** CloudFront (TLS, caching) → API Gateway (HTTP API)
- **Compute:** Lambda (Rust, arm64)
- **Data:** DynamoDB (on‑demand, TTL on `expires_at`)

**Routes**
- `POST /v1/links` → create short link (optionally specify `slug` and `expires_at`)
- `GET /{slug}` → 301 redirect to target (with cache headers)
- `GET /v1/links/{slug}` → (optional) fetch link metadata

## Quickstart

### 0) Prereqs
- Rust stable + `cargo`
- `cargo-lambda` (`cargo install cargo-lambda`)
- Terraform ≥ 1.5
- AWS credentials with permissions for: Lambda, API GW, DynamoDB, CloudFront, ACM, Route53

### 1) Build Lambda (arm64)
```bash
make build
```

Artifact will be at `target/lambda/quickshort/bootstrap.zip`.

### 2) Deploy infra

```bash
cd deployments/terraform
terraform init
terraform apply \
  -var domain_name="codequesthub.io" \
  -var subdomain="go" \
  -var aws_region_lambda="us-west-2"
```

After `apply`, note outputs: `cloudfront_domain`, `api_invoke_url`, `ddb_table`.

### 3) Create a link

```bash
curl -X POST "https://go.codequesthub.io/v1/links" \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://codequesthub.io/", "expires_at": null}'
```

→ `{ "slug": "aB9d2", "short_url": "https://go.codequesthub.io/aB9d2" }`

### 4) Resolve

```bash
curl -i https://go.codequesthub.io/aB9d2
```

→ `HTTP/1.1 301 Moved Permanently` with `Location: https://codequesthub.io/`

## Environment

* `TABLE_NAME` (set by Terraform)
* `CACHE_MAX_AGE` (default `86400` seconds)
* `LOG_LEVEL` (`info`)

## Design Notes

* Base62 slugs derived from BLAKE3 hash of `(url || created_at || random)`; on collision, re‑salt and retry (DDB conditional put).
* TTL uses DynamoDB numeric epoch seconds stored in `expires_at` (optional).
* Redirect responses return `Cache-Control: public, max-age=$CACHE_MAX_AGE` so CloudFront can absorb reads.

## Testing

```bash
cargo test
```

## License

MIT

