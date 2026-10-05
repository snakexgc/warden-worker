use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use chrono::Utc;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::{db, error::AppError, router::AppState};

fn parse_bool(input: &str, default: bool) -> bool {
    match input.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default,
    }
}

fn env_bool(env: &worker::Env, key: &str, default: bool) -> bool {
    env.var(key)
        .ok()
        .map(|value| parse_bool(&value.to_string(), default))
        .unwrap_or(default)
}

#[worker::send]
pub async fn config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    let user_exists: Option<i64> = db
        .prepare("SELECT 1 AS ok FROM users LIMIT 1")
        .first(Some("ok"))
        .await
        .map_err(|_| AppError::Database)?;
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    let domain = format!("{proto}://{host}");
    let suppress_onboarding = env_bool(&state.env, "CLIENT_SUPPRESS_ONBOARDING", false);
    Ok(Json(json!({
        "version": "2026.6.0",
        "gitHash": option_env!("GIT_REV"),
        "server": {
          "name": "Vaultwarden",
          "url": "https://github.com/dani-garcia/vaultwarden"
        },
        "settings": {
            "disableUserRegistration": user_exists.is_some(),
            "suppressOnboardingInterstitials": suppress_onboarding,
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
            "pm-19148-innovation-archive": true,
            "pm-32413-multi-client-password-management": true,
            "undetermined-cipher-scenario-logic": true,
            "windows-native-credential-sync": true,
            "enable-basic-auth-response": true,
            "pm-34171-card-scanner": true,
            "pm-32009-new-item-types": true
        },
        "communication": null,
        "object": "config",
    })))
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
    Json(Utc::now().to_rfc3339())
}

#[worker::send]
pub async fn alive(State(state): State<Arc<AppState>>) -> Result<Json<String>, AppError> {
    let db = db::get_db(&state.env)?;
    db.prepare("SELECT 1 AS ok")
        .first::<i64>(Some("ok"))
        .await
        .map_err(|_| AppError::Database)?
        .ok_or(AppError::Database)?;
    Ok(Json(Utc::now().to_rfc3339()))
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

#[cfg(test)]
mod tests {
    use super::parse_bool;

    #[test]
    fn client_boolean_values_follow_worker_configuration_conventions() {
        for enabled in ["1", "true", "TRUE", "yes", "on"] {
            assert!(parse_bool(enabled, false));
        }
        for disabled in ["0", "false", "FALSE", "no", "off"] {
            assert!(!parse_bool(disabled, true));
        }
        assert!(parse_bool("invalid", true));
        assert!(!parse_bool("invalid", false));
    }
}
