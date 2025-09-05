use aws_sdk_dynamodb as ddb;
use aws_sdk_dynamodb::error::ProvideErrorMetadata; // for .code()
use ddb::types::AttributeValue as Av;
use lambda_http::{Body, Error, Request, Response};
use serde_json::json;

use crate::{
    auth::{require_auth, Caller},
    handler::{json_err, map_ddb_err, Ctx},
    id::new_slug,
    model::{CreateReq, CreateResp},
    require_auth_or_return,
    util::{epoch_now, resp_json, valid_target},
};

pub(crate) async fn create_link(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let caller = require_auth_or_return!(req, 401, "unauthorized", "Requires authentication");

    let body_bytes = match req.body() {
        Body::Text(s) => s.as_bytes().to_vec(),
        Body::Binary(b) => b.clone(),
        _ => Vec::new(),
    };

    let payload: CreateReq =
        serde_json::from_slice(&body_bytes).map_err(|_| Error::from("bad json"))?;

    if !valid_target(&payload.target) {
        return Ok(resp_json(400, json!({"error":"invalid target"})));
    }

    let now = epoch_now();
    let mut attempt = 0u32;
    let slug = match &payload.slug {
        Some(s) => s.clone(),
        None => loop {
            attempt += 1;
            let candidate = new_slug(&payload.target, now, attempt);
            if try_put(
                ctx,
                &candidate,
                &payload.target,
                now,
                payload.expires_at,
                &caller,
            )
            .await?
            {
                break candidate;
            }
            if attempt > 6 {
                return Ok(resp_json(500, json!({"error":"exhausted attempts"})));
            }
        },
    };

    if payload.slug.is_some()
        && !try_put(
            ctx,
            &slug,
            &payload.target,
            now,
            payload.expires_at,
            &caller,
        )
        .await?
    {
        return Ok(resp_json(409, json!({"error":"slug exists"})));
    }

    let short = format!("https://{}/{}", ctx.domain, slug);
    let out = CreateResp {
        slug: slug.clone(),
        short_url: short,
        target: payload.target.clone(),
        expires_at: payload.expires_at,
    };
    Ok(resp_json(201, serde_json::to_value(out).unwrap()))
}

async fn try_put(
    ctx: &Ctx,
    slug: &str,
    target: &str,
    created_at: u64,
    expires_at: Option<u64>,
    caller: &Caller,
) -> Result<bool, Error> {
    let mut item = std::collections::HashMap::new();
    item.insert("slug".into(), Av::S(slug.to_string()));
    item.insert("target".into(), Av::S(target.to_string()));
    item.insert("created_at".into(), Av::N(created_at.to_string()));
    if let Some(ttl) = expires_at {
        item.insert("expires_at".into(), Av::N(ttl.to_string()));
    }
    item.insert("visits".into(), Av::N("0".into()));
    item.insert("status".into(), Av::S("active".into()));
    item.insert("owner_id".into(), Av::S(caller.user_id.clone()));

    let r = ctx
        .ddb
        .put_item()
        .table_name(&ctx.table)
        .set_item(Some(item))
        .condition_expression("attribute_not_exists(#s)")
        .expression_attribute_names("#s", "slug")
        .send()
        .await;

    match r {
        Ok(_) => Ok(true),
        Err(e) => {
            if e.code() == Some("ConditionalCheckFailedException") {
                return Ok(false);
            }
            Err(Error::from(format!("ddb put error: {:?}", e)))
        }
    }
}

pub(crate) async fn resolve_link(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let path = req.uri().path();
    if path.starts_with("/v1/") {
        return Ok(Response::builder()
            .status(404)
            .body("Not Found".into())
            .unwrap());
    }
    let slug = path.trim_start_matches('/');
    if slug.is_empty() {
        return Ok(Response::builder()
            .status(404)
            .body("Not Found".into())
            .unwrap());
    }

    let key = std::collections::HashMap::from([(String::from("slug"), Av::S(slug.to_string()))]);
    let r = ctx
        .ddb
        .get_item()
        .table_name(&ctx.table)
        .set_key(Some(key))
        .send()
        .await
        .map_err(|e| Error::from(format!("ddb get error: {e}")))?;

    let Some(item) = r.item else {
        return Ok(Response::builder()
            .status(404)
            .body("Not Found".into())
            .unwrap());
    };

    let target = item
        .get("target")
        .and_then(|v| v.as_s().ok())
        .cloned()
        .unwrap_or_default();

    let expires_at = item
        .get("expires_at")
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse::<u64>().ok());

    if let Some(ttl) = expires_at {
        if epoch_now() > ttl {
            return Ok(Response::builder()
                .status(404)
                .body("Not Found".into())
                .unwrap());
        }
    }

    // Best-effort visit increment (ignore errors)
    let _ = ctx
        .ddb
        .update_item()
        .table_name(&ctx.table)
        .key("slug", Av::S(slug.to_string()))
        .update_expression("ADD visits :inc")
        .expression_attribute_values(":inc", Av::N("1".into()))
        .send()
        .await;

    let resp = Response::builder()
        .status(301)
        .header("Location", target)
        .header(
            "Cache-Control",
            format!("public, max-age={}", ctx.cache_max_age),
        )
        .body(Body::Empty)
        .unwrap();
    Ok(resp)
}

pub(crate) async fn update_link(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let caller = require_auth_or_return!(req, 404, "not_found", "Slug not found");

    let path = req.uri().path();
    let slug = path.trim_start_matches("/v1/links/");
    if slug.is_empty() {
        return Ok(resp_json(400, json!({"error":"bad_slug"})));
    }

    if !caller.is_admin {
        // Fetch current item
        let item = ctx
            .ddb
            .get_item()
            .table_name(&ctx.table)
            .key("slug", Av::S(slug.to_string()))
            .send()
            .await
            .map_err(|e| lambda_http::Error::from(format!("ddb get: {e}")))?
            .item;

        let Some(item) = item else {
            return json_err(404, "not_found", "Slug not found");
        };
        let defaut_owner = "system".to_string();
        let owner = item
            .get("owner_id")
            .and_then(|v| v.as_s().ok())
            .unwrap_or(&defaut_owner);
        if owner != &caller.user_id {
            return json_err(404, "not_found", "Slug not found");
        }
    }

    let body_bytes = match req.body() {
        Body::Text(s) => s.as_bytes().to_vec(),
        Body::Binary(b) => b.clone(),
        _ => Vec::new(),
    };
    let v: serde_json::Value =
        serde_json::from_slice(&body_bytes).map_err(|_| Error::from("bad json"))?;

    let target = v.get("target").and_then(|x| x.as_str()).unwrap_or("");
    let expires_at = v.get("expires_at").and_then(|x| x.as_u64());

    if target.is_empty() && expires_at.is_none() {
        return Ok(resp_json(400, json!({"error":"no_updates"})));
    }

    let mut expr = String::from("SET ");
    let mut names = std::collections::HashMap::new();
    let mut vals = std::collections::HashMap::new();
    let mut first = true;

    if !target.is_empty() {
        if !first {
            expr.push_str(", ");
        }
        first = false;
        expr.push_str("#t = :t");
        names.insert("#t".to_string(), "target".to_string());
        vals.insert(":t".to_string(), Av::S(target.to_string()));
    }
    if let Some(exp) = expires_at {
        if !first {
            expr.push_str(", ");
        }
        expr.push_str("#e = :e");
        names.insert("#e".to_string(), "expires_at".to_string());
        vals.insert(":e".to_string(), Av::N(exp.to_string()));
    }

    ctx.ddb
        .update_item()
        .table_name(&ctx.table)
        .key("slug", Av::S(slug.to_string()))
        .update_expression(expr)
        .set_expression_attribute_names(Some(names))
        .set_expression_attribute_values(Some(vals))
        .return_values(aws_sdk_dynamodb::types::ReturnValue::UpdatedNew)
        .send()
        .await
        .map_err(map_ddb_err)?;

    Ok(resp_json(204, json!({})))
}

pub(crate) async fn list_links(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let caller = require_auth_or_return!(req, 401, "unauthorized", "Requires authentication");

    let qp = req.uri().query().unwrap_or("");
    let params: std::collections::HashMap<_, _> = url::form_urlencoded::parse(qp.as_bytes())
        .into_owned()
        .collect();
    let q = params.get("q").cloned().unwrap_or_default();
    let mine = params
        .get("mine")
        .map(|s| s == "true" || s == "1")
        .unwrap_or(!caller.is_admin);
    let mine = if caller.is_admin { false } else { mine };
    let limit: i32 = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(25);
    let next = params.get("next").cloned();

    if !mine {
        let mut scan = ctx.ddb.scan().table_name(&ctx.table).limit(limit);
        if !q.is_empty() {
            if let Some(rest) = q.strip_prefix("slug:") {
                scan = scan
                    .filter_expression("begins_with(#s, :p)")
                    .expression_attribute_names("#s", "slug")
                    .expression_attribute_values(":p", Av::S(rest.to_string()));
            } else {
                scan = scan
                    .filter_expression("contains(#t, :p)")
                    .expression_attribute_names("#t", "target")
                    .expression_attribute_values(":p", Av::S(q));
            }
        }

        let resp = scan.send().await.map_err(map_ddb_err)?;
        return Ok(list_response_to_json(
            resp.items(),
            resp.count(),
            resp.last_evaluated_key(),
        ));
    }

    let mut scan = ctx
        .ddb
        .query()
        .table_name(&ctx.table)
        .index_name("GSI1-owner")
        .key_condition_expression("owner_id = :o")
        .expression_attribute_values(":o", Av::S(caller.user_id))
        .limit(limit);

    if let Some(slug_tok) = next {
        let mut esk = std::collections::HashMap::new();
        esk.insert("slug".to_string(), Av::S(slug_tok));
        scan = scan.set_exclusive_start_key(Some(esk));
    }

    if !q.is_empty() {
        if let Some(rest) = q.strip_prefix("slug:") {
            scan = scan
                .filter_expression("begins_with(#s, :p)")
                .expression_attribute_names("#s", "slug")
                .expression_attribute_values(":p", Av::S(rest.to_string()));
        } else {
            scan = scan
                .filter_expression("contains(#t, :p)")
                .expression_attribute_names("#t", "target")
                .expression_attribute_values(":p", Av::S(q));
        }
    }

    let resp = scan.send().await.map_err(map_ddb_err)?;
    Ok(list_response_to_json(
        resp.items(),
        resp.count(),
        resp.last_evaluated_key(),
    ))
}

fn list_response_to_json(
    items: &[::std::collections::HashMap<
        ::std::string::String,
        aws_sdk_dynamodb::types::AttributeValue,
    >],
    count: i32,
    lek: Option<&std::collections::HashMap<String, Av>>,
) -> Response<Body> {
    let items: Vec<_> = items.iter().map(|it| {
        json!({
            "slug": it.get("slug").and_then(|v| v.as_s().ok()),
            "target": it.get("target").and_then(|v| v.as_s().ok()),
            "created_at": it.get("created_at").and_then(|v| v.as_n().ok()).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
            "visits": it.get("visits").and_then(|v| v.as_n().ok()).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
            "expires_at": it.get("expires_at").and_then(|v| v.as_n().ok()).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
            "status": it.get("status").and_then(|v| v.as_s().ok()),
            "owner_id": it.get("owner_id").and_then(|v| v.as_s().ok()),
        })
    }).collect();

    let mut out = json!({ "items": items, "count": count });
    if let Some(lek) = lek {
        if let Some(Av::S(slug)) = lek.get("slug") {
            out["next"] = json!(slug);
        }
    }

    resp_json(200, out)
}

pub(crate) async fn delete_link(req: Request, ctx: &Ctx) -> Result<Response<Body>, Error> {
    let caller = require_auth_or_return!(req, 404, "not_found", "Slug not found");

    let slug = req
        .uri()
        .path()
        .trim_start_matches("/v1/links/")
        .to_string();
    if slug.is_empty() {
        return Ok(resp_json(400, json!({"error":"missing slug"})));
    }

    if !caller.is_admin {
        // Fetch current item
        let item = ctx
            .ddb
            .get_item()
            .table_name(&ctx.table)
            .key("slug", Av::S(slug.to_string()))
            .send()
            .await
            .map_err(|e| lambda_http::Error::from(format!("ddb get: {e}")))?
            .item;
        let Some(item) = item else {
            return json_err(404, "not_found", "Slug not found");
        };
        let owner = item
            .get("owner_id")
            .and_then(|v| v.as_s().ok())
            .map_or("system", |v| v);
        if owner != caller.user_id {
            return json_err(404, "not_found", "Slug not found");
        };
    }

    ctx.ddb
        .delete_item()
        .table_name(&ctx.table)
        .key("slug", Av::S(slug))
        .send()
        .await
        .map_err(|e| Error::from(format!("ddb delete: {:?}", e)))?;

    Ok(Response::builder().status(204).body(Body::Empty).unwrap())
}
