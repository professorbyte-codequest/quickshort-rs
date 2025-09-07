mod admin;
mod api;
mod auth;
mod handler;
mod id;
mod limits;
mod model;
mod oauth;
mod users;
mod util;

use handler::Ctx;
use lambda_http::{run, service_fn, Error, Request};

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::INFO)
        // this needs to be set to remove duplicated information in the log.
        .with_current_span(false)
        // this needs to be set to false, otherwise ANSI color codes will
        // show up in a confusing manner in CloudWatch logs.
        .with_ansi(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        // remove the name of the function from every log entry
        .with_target(false)
        .init();

    let ctx = Ctx::new().await;

    // Clone once for the service closure; cheap (Client is Clone)
    let ctx_for_service = ctx.clone();

    run(service_fn(move |req: Request| {
        let ctx = ctx_for_service.clone();
        async move { handler::router(req, &ctx).await }
    }))
    .await
}
