use axum::{extract::State, http::HeaderMap, Json};
use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::router::AppState;

#[worker::send]
pub async fn config(
    State(_state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Json<Value> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    let domain = format!("{proto}://{host}");
    Json(json!({
        "version": "2025.12.0",
        "gitHash": "25cf6119-dirty",
        "server": {
          "name": "Vaultwarden",
          "url": "https://github.com/dani-garcia/vaultwarden"
        },
        "settings": {
            "disableUserRegistration": true,
        },
        "environment": {
          "vault": domain,
          "api": format!("{domain}/api"),
          "identity": format!("{domain}/identity"),
          "notifications": format!("{domain}/notifications"),
          "sso": null,
          "cloudRegion": null,
        },
        "push": {
          "pushTechnology": 0,
          "vapidPublicKey": null
        },
        "featureStates": {
            "unauth-ui-refresh": true
        },
        "object": "config",
    }))
}

#[worker::send]
pub async fn now(State(_state): State<Arc<AppState>>) -> Json<String> {
    Json(Utc::now().to_rfc3339())
}

#[worker::send]
pub async fn alive(State(_state): State<Arc<AppState>>) -> Json<String> {
    now(State(_state)).await
}

#[worker::send]
pub async fn version(State(_state): State<Arc<AppState>>) -> Json<&'static str> {
    Json("2025.12.0")
}

#[worker::send]
pub async fn webauthn(State(_state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    }))
}
