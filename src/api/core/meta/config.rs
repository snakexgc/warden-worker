use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use chrono::Utc;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::{api::AppState, db, error::AppError};

#[worker::send]
pub async fn config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let signups_allowed = env_bool(&state.env, "SIGNUPS_ALLOWED", true);
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    let domain = format!("{proto}://{host}");
    Ok(Json(json!({
        "version": "2026.6.0",
        "gitHash": option_env!("GIT_REV"),
        "server": {
          "name": "Vaultwarden",
          "url": "https://github.com/dani-garcia/vaultwarden"
        },
        "settings": {
            "disableUserRegistration": !signups_allowed,
            "suppressOnboardingInterstitials": false,
        },
        "environment": {
          "vault": domain,
          "api": format!("{domain}/api"),
          "identity": format!("{domain}/identity"),
          "notifications": format!("{domain}/notifications"),
          "sso": "",
          "cloudRegion": null,
        },
        "push": {
          "pushTechnology": 0,
          "vapidPublicKey": null
        },
        "featureStates": {
            "pm-19148-innovation-archive": true
        },
        "communication": null,
        "object": "config",
    })))
}

fn env_bool(env: &worker::Env, name: &str, default: bool) -> bool {
    let value = env
        .var(name)
        .ok()
        .map(|value| value.to_string())
        .or_else(|| env.secret(name).ok().map(|value| value.to_string()));
    match value.as_deref().map(str::trim).map(str::to_ascii_lowercase) {
        Some(value) if matches!(value.as_str(), "1" | "true" | "yes" | "on") => true,
        Some(value) if matches!(value.as_str(), "0" | "false" | "no" | "off") => false,
        _ => default,
    }
}

#[worker::send]
pub async fn apple_app_site_association(State(_state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "webcredentials": {
            "apps": [
                "LTZ2PFU5D6.com.8bit.bitwarden",
                "LTZ2PFU5D6.com.8bit.bitwarden.beta"
            ]
        }
    }))
}

#[worker::send]
pub async fn now(State(_state): State<Arc<AppState>>) -> Json<String> {
    // 对齐 Vaultwarden format_date：固定微秒 + Z
    Json(Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
}

#[worker::send]
pub async fn alive(State(state): State<Arc<AppState>>) -> Result<Json<String>, AppError> {
    let db = db::get_db(&state.env)?;
    db.prepare("SELECT 1 AS ok")
        .first::<i64>(Some("ok"))
        .await
        .map_err(|_| AppError::Database)?
        .ok_or(AppError::Database)?;
    Ok(Json(
        Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
    ))
}

#[worker::send]
pub async fn alive_head(State(state): State<Arc<AppState>>) -> Result<StatusCode, AppError> {
    let db = db::get_db(&state.env)?;
    db.prepare("SELECT 1 AS ok")
        .first::<i64>(Some("ok"))
        .await
        .map_err(|_| AppError::Database)?
        .ok_or(AppError::Database)?;
    Ok(StatusCode::OK)
}

#[worker::send]
pub async fn version(State(_state): State<Arc<AppState>>) -> Json<&'static str> {
    Json(env!("CARGO_PKG_VERSION"))
}

#[worker::send]
pub async fn webauthn(State(_state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    }))
}
