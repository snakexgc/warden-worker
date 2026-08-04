#![recursion_limit = "256"]

use tower_http::cors::{Any, CorsLayer};
use tower_service::Service;
use worker::*;

mod auth;
mod background;
mod crypto;
mod db;
mod domains;
mod error;
mod handlers;
mod heavy_do;
mod jwt;
mod jwt_manager;
mod logging;
mod models;
mod notifications;
mod notify;
mod password;
mod r2_file;
mod router;
mod two_factor;
mod two_factor_key_manager;
mod webauthn;

pub use heavy_do::HeavyDo;

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

    let db = env
        .d1("vaultsql")
        .map_err(|e| worker::Error::RustError(format!("Failed to get database: {}", e)))?;

    let jwt_keys = jwt_manager::JwtKeyManager::get_or_create_keys(&db)
        .await
        .map_err(|e| worker::Error::RustError(format!("Failed to initialize JWT keys: {}", e)))?;

    let two_factor_key = two_factor_key_manager::TwoFactorKeyManager::get_or_create_key(&db)
        .await
        .map_err(|e| {
            worker::Error::RustError(format!("Failed to initialize two-factor key: {}", e))
        })?;

    let (city, region, country) = {
        if let Some(cf) = req.cf() {
            (cf.city(), cf.region(), cf.country())
        } else {
            (None, None, None)
        }
    };

    let mut http_req: HttpRequest = req
        .try_into()
        .map_err(|e| worker::Error::RustError(format!("Failed to convert request: {}", e)))?;

    let mut inject = |k: &'static str, v: Option<String>| {
        if let Some(v) = v
            && let Ok(hv) = axum::http::HeaderValue::from_str(&v)
        {
            http_req.headers_mut().insert(k, hv);
        }
    };
    inject("X-CF-City", city);
    inject("X-CF-Region", region);
    inject("X-CF-Country", country);

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    let mut app =
        router::api_router_with_keys(env, Some(ctx), jwt_keys, two_factor_key).layer(cors);

    Ok(Service::call(&mut app, http_req).await?)
}

#[event(scheduled)]
pub async fn scheduled(event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    console_error_panic_hook::set_once();
    logging::init_logging(&env);
    match notify::outbox::deliver_pending(&env, 40).await {
        Ok(count) if count > 0 => log::info!("scheduled notification retry processed {count} rows"),
        Ok(_) => {}
        Err(err) => log::error!("scheduled notification retry failed: {err}"),
    }
    if event.cron() == "0 3 * * *" {
        match handlers::sends::purge_expired_sends(&env).await {
            Ok(count) => log::info!("scheduled cleanup purged {count} expired Sends"),
            Err(err) => log::error!("scheduled expired Send cleanup failed: {err}"),
        }
        if let Err(err) = notify::outbox::purge_expired(&env).await {
            log::error!("scheduled notification/token cleanup failed: {err}");
        }
    }
}
