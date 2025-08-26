mod handler;
mod id;
mod model;
mod util;

use handler::Ctx;
use lambda_http::{run, service_fn, Error, Request};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
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
