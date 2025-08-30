use aws_config::{BehaviorVersion, Region};
use aws_lambda_events::event::kinesis::KinesisEvent;
use aws_sdk_dynamodb::{types::AttributeValue as AV, Client as DdbClient};
use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde_json::Value as Json;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let func = service_fn(handler);
    lambda_runtime::run(func).await
}

async fn handler(event: LambdaEvent<KinesisEvent>) -> Result<(), Error> {
    // Prepare DDB client targeting the table's region (may differ from Lambda region)
    let table = std::env::var("TABLE_NAME").expect("TABLE_NAME");
    let table_region = std::env::var("TABLE_REGION").unwrap_or_else(|_| "us-west-2".into());

    let mut loader = aws_config::defaults(BehaviorVersion::latest());
    loader = loader.region(Region::new(table_region.clone()));
    let conf = loader.load().await;
    let ddb = DdbClient::new(&conf);

    // Aggregate counts per slug for this batch
    let mut counts: HashMap<String, u64> = HashMap::new();

    for rec in event.payload.records {
        // Kinesis data is base64; aws_lambda_events gives bytes
        let data = match std::str::from_utf8(&rec.kinesis.data.0) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Each record is typically a single JSON object per line
        // Example fields we requested: timestamp, cs-host, cs-uri-stem, sc-status, x-cache, x-edge-result-type
        // Some delivery configs send one object per line; others may send an array — handle both.
        if let Ok(val) = serde_json::from_str::<Json>(data) {
            match val {
                Json::Array(arr) => {
                    for obj in arr {
                        if let Some(slug) = extract_slug_if_redirect(&obj) {
                            *counts.entry(slug).or_insert(0) += 1;
                        }
                    }
                }
                Json::Object(_) => {
                    if let Some(slug) = extract_slug_if_redirect(&val) {
                        *counts.entry(slug).or_insert(0) += 1;
                    }
                }
                _ => {}
            }
        }
    }

    // Batch write: one UpdateItem per slug
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (slug, n) in counts {
        // Ignore admin/api paths just in case
        if slug.is_empty() || slug.starts_with("v1/") || slug.starts_with("admin") {
            continue;
        }
        let _ = ddb
            .update_item()
            .table_name(&table)
            .key("slug", AV::S(slug))
            .update_expression("ADD visits :inc SET last_visit = :ts")
            .expression_attribute_values(":inc", AV::N(n.to_string()))
            .expression_attribute_values(":ts", AV::N(now.to_string()))
            .send()
            .await;
    }

    Ok(())
}

fn extract_slug_if_redirect(obj: &Json) -> Option<String> {
    // status 301/302 only
    let status = obj
        .get("sc-status")
        .or_else(|| obj.get("sc_status"))?
        .as_i64()?;
    if status != 301 && status != 302 {
        return None;
    }

    // pull the path, strip leading '/'
    let stem = obj
        .get("cs-uri-stem")
        .or_else(|| obj.get("cs_uri_stem"))?
        .as_str()?;
    let stem = stem.trim_start_matches('/');
    if stem.is_empty() {
        return None;
    }

    // exclude known non-slug paths
    if stem.starts_with("v1/") || stem.starts_with("admin") {
        return None;
    }

    Some(stem.to_string())
}
