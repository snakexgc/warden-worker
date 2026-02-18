use tower_http::cors::{Any, CorsLayer};
use tower_service::Service;
use worker::*;

mod auth;
mod crypto;
mod db;
mod domains;
mod error;
mod handlers;
mod logging;
mod models;
mod notify;
mod router;
mod two_factor;

#[event(fetch)]
pub async fn main(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();
    let log_level = logging::init_logging(&env);
    log::info!(target: logging::targets::API, "Logging initialized at level: {:?}", log_level);

    // Allow all origins for CORS, which is typical for a public API like Bitwarden's.
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    let mut app = router::api_router(env).layer(cors);

    Ok(app.call(req).await?)
}
