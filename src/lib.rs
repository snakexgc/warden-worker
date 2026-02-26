use tower_http::cors::{Any, CorsLayer};
use tower_service::Service;
use worker::*;

mod auth;
mod crypto;
mod db;
mod domains;
mod error;
mod handlers;
mod jwt;
mod logging;
mod models;
mod notify;
mod notifications;
mod router;
mod two_factor;
mod webauthn;

#[event(fetch)]
pub async fn main(
    req: Request,
    env: Env,
    ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();
    let log_level = logging::init_logging(&env);
    log::info!(target: logging::targets::API, "Logging initialized at level: {:?}", log_level);

    if notifications::is_notifications_path(&req.path()) {
        let worker_resp = notifications::proxy_notifications_request(&env, req).await?;
        return Ok(worker_resp.into());
    }

    let (city, region, country) = {
        if let Some(cf) = req.cf() {
            (cf.city(), cf.region(), cf.country())
        } else {
            (None, None, None)
        }
    };

    let mut http_req: HttpRequest = req.try_into().map_err(|e| worker::Error::RustError(format!("Failed to convert request: {}", e)))?;

    let mut inject = |k: &'static str, v: Option<String>| {
        if let Some(v) = v {
            if let Ok(hv) = axum::http::HeaderValue::from_str(&v) {
                http_req.headers_mut().insert(k, hv);
            }
        }
    };
    inject("X-CF-City", city);
    inject("X-CF-Region", region);
    inject("X-CF-Country", country);

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    let mut app = router::api_router(env, ctx).layer(cors);

    Ok(Service::call(&mut app, http_req).await?)
}
