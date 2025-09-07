// =============================================
// Quotas & Token Bucket for Link Creation
// =============================================
// Implements per-user limits:
//  - Token bucket (burst/rate) for link creation
//  - Monthly quota (max links created per calendar month)
//  - Total quota (lifetime max links)
//
// DynamoDB table: quickshort-usage
//   PK: user_id (S)
//   SK: k (S) — one of
//       "bucket:links"                (token bucket)
//       "month:links:YYYYMM"          (monthly quota)
//       "total:links"                 (total quota)
//   Attributes:
//     tokens (N), capacity (N), refill_rate (N), last_refill (N seconds)
//     count (N), limit (N), reset_at (S), ttl (N epoch seconds)
//     plan (S)
//
// IAM: lambda must have UpdateItem/GetItem on this table
// Env:
//   TABLE_USAGE                  : table name
//   FREE_MONTHLY_LINKS           : e.g. 50
//   FREE_TOTAL_LINKS             : e.g. 200
//   FREE_BUCKET_CAPACITY         : e.g. 10
//   FREE_BUCKET_REFILL_PER_SEC   : e.g. 0.5
//   (future: PRO, TEAM, ...)
//
// Usage in handler (create link):
//   let caller = require_auth(&req).await?;
//   limits::enforce_link_create(&ctx, &caller).await?; // returns 429-style error on limit
//   ... then proceed to write link

use aws_sdk_dynamodb as ddb;
use aws_sdk_dynamodb::error::ProvideErrorMetadata;
use aws_sdk_dynamodb::types::AttributeValue as Av;
use chrono::{Datelike, TimeZone, Utc};
use lambda_http::{Body, Error, Response};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct LimitsCtx {
    pub ddb: ddb::Client,
    pub table_usage: String,
}

#[derive(Debug, Clone)]
pub struct PlanLimits {
    pub monthly_links: u32,
    pub total_links: u32,
    pub bucket_capacity: u32,
    pub bucket_refill_per_sec: f64,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn plan_limits(plan: &str) -> PlanLimits {
    // For now only free; load from env with sensible defaults
    let env_u32 = |k: &str, d: u32| {
        std::env::var(k)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(d)
    };
    let env_f64 = |k: &str, d: f64| {
        std::env::var(k)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(d)
    };
    match plan.to_ascii_lowercase().as_str() {
        "free" | _ => PlanLimits {
            monthly_links: env_u32("FREE_MONTHLY_LINKS", 50),
            total_links: env_u32("FREE_TOTAL_LINKS", 200),
            bucket_capacity: env_u32("FREE_BUCKET_CAPACITY", 10),
            bucket_refill_per_sec: env_f64("FREE_BUCKET_REFILL_PER_SEC", 0.5), // 1 token per 2s
        },
    }
}

#[derive(Debug)]
pub enum LimitErrorKind {
    RateLimited { retry_after_secs: u32 },
    MonthlyExhausted,
    TotalExhausted,
}

#[derive(Debug)]
pub struct LimitError(pub LimitErrorKind);

impl From<LimitError> for lambda_http::Error {
    fn from(e: LimitError) -> Self {
        // Map to a 429 payload; caller can use `json_err(429, ..)` wrappers if preferred.
        let (code, msg) = match e.0 {
            LimitErrorKind::RateLimited { retry_after_secs } => (
                429,
                format!("rate_limited; retry_after_secs={}", retry_after_secs),
            ),
            LimitErrorKind::MonthlyExhausted => (429, "monthly_quota_exhausted".to_string()),
            LimitErrorKind::TotalExhausted => (429, "total_quota_exhausted".to_string()),
        };
        lambda_http::Error::from(format!("{}", msg))
    }
}

pub async fn enforce_link_create(
    ctx: &LimitsCtx,
    caller: &crate::auth::Caller,
    plan: &str,
) -> Result<(), LimitError> {
    // Legacy admins bypass limits
    if caller.is_admin {
        return Ok(());
    }

    let lim = plan_limits(plan);
    let user_id = caller.user_id.as_str();

    // 1) Rate limit via token bucket
    token_bucket_consume(
        ctx,
        user_id,
        "bucket:links",
        lim.bucket_capacity,
        lim.bucket_refill_per_sec,
        1,
    )
    .await?;

    // 2) Monthly quota
    monthly_increment(ctx, user_id, plan, lim.monthly_links, 1).await?;

    // 3) Total quota
    total_increment(ctx, user_id, plan, lim.total_links, 1).await?;

    Ok(())
}

// ----------------- Token bucket -----------------

async fn token_bucket_consume(
    ctx: &LimitsCtx,
    user_id: &str,
    bucket_key: &str,
    capacity: u32,
    refill_per_sec: f64,
    n: u32,
) -> Result<(), LimitError> {
    // retry CAS up to a few times to avoid races
    for _ in 0..4 {
        // Read current
        let got = ctx
            .ddb
            .get_item()
            .table_name(&ctx.table_usage)
            .key("user_id", Av::S(user_id.to_string()))
            .key("k", Av::S(bucket_key.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("ddb get bucket: {:?}", e);
                LimitError(LimitErrorKind::RateLimited {
                    retry_after_secs: 1,
                })
            })?;

        let now = now_secs();
        let (prev_tokens, prev_lr) = if let Some(item) = got.item() {
            let t = item
                .get("tokens")
                .and_then(|v| v.as_n().ok())
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0);
            let lr = item
                .get("last_refill")
                .and_then(|v| v.as_n().ok())
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(now);
            (t, lr)
        } else {
            (capacity as f64, now)
        };

        // Refill
        let elapsed = (now - prev_lr).max(0) as f64;
        let mut tokens_now = (prev_tokens + elapsed * refill_per_sec).min(capacity as f64);
        if tokens_now < n as f64 {
            let needed = (n as f64 - tokens_now) / refill_per_sec;
            let retry = needed.ceil() as u32;
            return Err(LimitError(LimitErrorKind::RateLimited {
                retry_after_secs: retry.max(1),
            }));
        }
        tokens_now -= n as f64;

        // CAS update
        let res = ctx
            .ddb
            .update_item()
            .table_name(&ctx.table_usage)
            .key("user_id", Av::S(user_id.to_string()))
            .key("k", Av::S(bucket_key.to_string()))
            .update_expression(
                "SET tokens = :t, last_refill = :lr, capacity = :cap, refill_rate = :rr",
            )
            .condition_expression(
                "attribute_not_exists(tokens) OR (tokens = :pt AND last_refill = :plr)",
            )
            .expression_attribute_values(":t", Av::N(format!("{:.6}", tokens_now)))
            .expression_attribute_values(":lr", Av::N(now.to_string()))
            .expression_attribute_values(":cap", Av::N(capacity.to_string()))
            .expression_attribute_values(":rr", Av::N(format!("{:.6}", refill_per_sec)))
            .expression_attribute_values(":pt", Av::N(format!("{:.6}", prev_tokens)))
            .expression_attribute_values(":plr", Av::N(prev_lr.to_string()))
            .return_values(ddb::types::ReturnValue::None)
            .send()
            .await;

        match res {
            Ok(_) => return Ok(()),
            Err(e) => {
                if e.code() == Some("ConditionalCheckFailedException") {
                    // lost the race — retry
                    continue;
                }
                tracing::error!(
                    "ddb update bucket err: code={:?} msg={:?}",
                    e.code(),
                    e.message()
                );
                return Err(LimitError(LimitErrorKind::RateLimited {
                    retry_after_secs: 1,
                }));
            }
        }
    }
    // too much contention — treat as rate limited briefly
    Err(LimitError(LimitErrorKind::RateLimited {
        retry_after_secs: 1,
    }))
}

// ----------------- Monthly quota -----------------

async fn monthly_increment(
    ctx: &LimitsCtx,
    user_id: &str,
    plan: &str,
    limit: u32,
    n: u32,
) -> Result<(), LimitError> {
    let now = Utc::now();
    let ym = format!("{:04}{:02}", now.year(), now.month());
    let reset_at = Utc
        .with_ymd_and_hms(now.year(), now.month(), 1, 0, 0, 0)
        .unwrap()
        .with_month(now.month() % 12 + 1)
        .unwrap()
        .format("%Y-%m-01T00:00:00Z")
        .to_string();
    let next_month_ts = {
        let next = if now.month() == 12 {
            Utc.with_ymd_and_hms(now.year() + 1, 1, 1, 0, 0, 0).unwrap()
        } else {
            Utc.with_ymd_and_hms(now.year(), now.month() + 1, 1, 0, 0, 0)
                .unwrap()
        };
        next.timestamp()
    };

    let remaining = (limit as i64 - n as i64).max(0) as u32;

    let resp = ctx.ddb
        .update_item()
        .table_name(&ctx.table_usage)
        .key("user_id", Av::S(user_id.to_string()))
        .key("k", Av::S(format!("month:links:{}", ym)))
        .update_expression("SET #limit = if_not_exists(#limit, :lim), plan = :plan, reset_at = if_not_exists(reset_at, :reset), ttl = if_not_exists(ttl, :ttl) ADD #count :inc")
        .condition_expression("if_not_exists(#count, :zero) <= :rem")
        .expression_attribute_names("#count", "count")
        .expression_attribute_names("#limit", "limit")
        .expression_attribute_values(":inc",  Av::N(n.to_string()))
        .expression_attribute_values(":lim",  Av::N(limit.to_string()))
        .expression_attribute_values(":plan", Av::S(plan.to_string()))
        .expression_attribute_values(":reset",Av::S(reset_at))
        .expression_attribute_values(":ttl",  Av::N(next_month_ts.to_string()))
        .expression_attribute_values(":zero", Av::N("0".into()))
        .expression_attribute_values(":rem",  Av::N(remaining.to_string()))
        .return_values(ddb::types::ReturnValue::None)
        .send().await;

    match resp {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.code() == Some("ConditionalCheckFailedException") {
                return Err(LimitError(LimitErrorKind::MonthlyExhausted));
            }
            tracing::error!(
                "ddb monthly update err: code={:?} msg={:?}",
                e.code(),
                e.message()
            );
            Err(LimitError(LimitErrorKind::MonthlyExhausted))
        }
    }
}

// ----------------- Total quota -----------------

async fn total_increment(
    ctx: &LimitsCtx,
    user_id: &str,
    plan: &str,
    limit: u32,
    n: u32,
) -> Result<(), LimitError> {
    let remaining = (limit as i64 - n as i64).max(0) as u32;

    let resp = ctx
        .ddb
        .update_item()
        .table_name(&ctx.table_usage)
        .key("user_id", Av::S(user_id.to_string()))
        .key("k", Av::S("total:links".to_string()))
        .update_expression("SET #limit = if_not_exists(#limit, :lim), plan = :plan ADD #count :inc")
        .condition_expression("if_not_exists(#count, :zero) <= :rem")
        .expression_attribute_names("#count", "count")
        .expression_attribute_names("#limit", "limit")
        .expression_attribute_values(":inc", Av::N(n.to_string()))
        .expression_attribute_values(":lim", Av::N(limit.to_string()))
        .expression_attribute_values(":plan", Av::S(plan.to_string()))
        .expression_attribute_values(":zero", Av::N("0".into()))
        .expression_attribute_values(":rem", Av::N(remaining.to_string()))
        .return_values(ddb::types::ReturnValue::None)
        .send()
        .await;

    match resp {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.code() == Some("ConditionalCheckFailedException") {
                return Err(LimitError(LimitErrorKind::TotalExhausted));
            }
            tracing::error!(
                "ddb total update err: code={:?} msg={:?}",
                e.code(),
                e.message()
            );
            Err(LimitError(LimitErrorKind::TotalExhausted))
        }
    }
}

// ------------- HTTP helpers (optional) -------------

pub fn limit_err_response(e: LimitErrorKind) -> Response<Body> {
    let (code, js) = match e {
        LimitErrorKind::RateLimited { retry_after_secs } => (
            429,
            serde_json::json!({
                "error": "rate_limited", "retry_after_secs": retry_after_secs
            }),
        ),
        LimitErrorKind::MonthlyExhausted => (
            429,
            serde_json::json!({ "error": "monthly_quota_exhausted" }),
        ),
        LimitErrorKind::TotalExhausted => {
            (429, serde_json::json!({ "error": "total_quota_exhausted" }))
        }
    };
    let body = serde_json::to_string(&js).unwrap();
    Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .body(Body::Text(body))
        .unwrap()
}

// ------------- Integrate in your create-link handler -------------
// Example snippet:
//
// pub async fn create_link(req: Request, ctx: &Ctx, lim_ctx: &limits::LimitsCtx) -> Result<Response<Body>, Error> {
//     let caller = require_auth(&req).await?;
//     if let Err(e) = limits::enforce_link_create(lim_ctx, &caller, None).await {
//         return Ok(limits::limit_err_response(e.0));
//     }
//     // proceed with DDB put into links table…
// }
