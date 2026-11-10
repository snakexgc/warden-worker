use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use chrono::Utc;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::{db, error::AppError, router::AppState};

const DEFAULT_FILL_ASSIST_RULES_URL: &str = "https://fillassist.bitwarden.com";

/// Feature flags clients may enable through the `CLIENT_FEATURE_FLAGS` env
/// var. Mirrors upstream `SUPPORTED_FEATURE_FLAGS`; flags already enabled by
/// default below can still be listed (and are a no-op) or turned off with
/// `name=false`.
const SUPPORTED_CLIENT_FEATURE_FLAGS: &[&str] = &[
    // Auth Team
    "pm-5594-safari-account-switching",
    "pm-32413-multi-client-password-management",
    // Autofill Team
    "undetermined-cipher-scenario-logic",
    "enable-basic-auth-response",
    "fill-assist-targeting-rules",
    "ssh-agent-v2",
    "windows-desktop-autotype",
    "windows-desktop-autotype-ga",
    // Key Management Team
    "biometrics-sdk-ipc",
    "windows-native-credential-sync",
    // Mobile Team
    "pm-34171-card-scanner",
    // Platform Team
    "pm-30529-webauthn-related-origins",
    // Vault Team
    "pm-32009-new-item-types",
];

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

/// A valid fill-assist rules URL is HTTPS, has a host and carries no
/// credentials, query or fragment (mirrors upstream validation of
/// `FILL_ASSIST_RULES_URL`).
fn is_valid_fill_assist_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed.has_host()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && url.trim() == url
}

fn fill_assist_rules_url(env: &worker::Env) -> String {
    match env.var("FILL_ASSIST_RULES_URL") {
        Ok(value) => {
            let value = value.to_string();
            if is_valid_fill_assist_url(&value) {
                value
            } else {
                log::warn!(
                    "invalid FILL_ASSIST_RULES_URL {:?}, falling back to default",
                    value
                );
                DEFAULT_FILL_ASSIST_RULES_URL.to_string()
            }
        }
        Err(_) => DEFAULT_FILL_ASSIST_RULES_URL.to_string(),
    }
}

/// Parses the `CLIENT_FEATURE_FLAGS` env var: a comma-separated list of
/// `name` or `name=bool` entries. Unknown flag names are dropped with a
/// warning, matching upstream's `EXPERIMENTAL_CLIENT_FEATURE_FLAGS`.
fn parse_client_feature_flags(input: &str) -> Vec<(String, bool)> {
    input
        .split(',')
        .map(str::trim)
        .filter(|flag| !flag.is_empty())
        .filter_map(|flag| {
            let (name, value) = match flag.split_once('=') {
                Some((name, value)) => (name.trim().to_owned(), parse_bool(value, true)),
                None => (flag.to_owned(), true),
            };
            if !SUPPORTED_CLIENT_FEATURE_FLAGS.contains(&name.as_str()) {
                log::warn!("ignoring unsupported CLIENT_FEATURE_FLAGS entry: {name}");
                return None;
            }
            Some((name, value))
        })
        .collect()
}

fn feature_states(env: &worker::Env) -> serde_json::Map<String, Value> {
    let mut states = serde_json::Map::new();
    for (flag, enabled) in [
        ("pm-19148-innovation-archive", true),
        ("pm-32413-multi-client-password-management", true),
        ("undetermined-cipher-scenario-logic", true),
        ("windows-native-credential-sync", true),
        ("enable-basic-auth-response", true),
        ("pm-34171-card-scanner", true),
        ("pm-32009-new-item-types", true),
    ] {
        states.insert(flag.to_string(), json!(enabled));
    }
    if let Ok(configured) = env.var("CLIENT_FEATURE_FLAGS") {
        for (flag, enabled) in parse_client_feature_flags(&configured.to_string()) {
            states.insert(flag, json!(enabled));
        }
    }
    states
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
          "fillAssistRules": fill_assist_rules_url(&state.env),
        },
        "push": {
          "pushTechnology": 0,
          "vapidPublicKey": null
        },
        "featureStates": Value::Object(feature_states(&state.env)),
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
    use super::{
        SUPPORTED_CLIENT_FEATURE_FLAGS, is_valid_fill_assist_url, parse_bool,
        parse_client_feature_flags,
    };

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

    #[test]
    fn fill_assist_url_validation_matches_upstream_rules() {
        assert!(is_valid_fill_assist_url("https://fillassist.bitwarden.com"));
        assert!(is_valid_fill_assist_url("https://example.com/rules.json"));
        assert!(!is_valid_fill_assist_url("http://example.com"));
        assert!(!is_valid_fill_assist_url("https://example.com/rules?q=1"));
        assert!(!is_valid_fill_assist_url("https://example.com/rules#frag"));
        assert!(!is_valid_fill_assist_url("https://user:pass@example.com"));
        assert!(!is_valid_fill_assist_url(" https://example.com "));
        assert!(!is_valid_fill_assist_url("not-a-url"));
    }

    #[test]
    fn client_feature_flags_parse_names_and_booleans() {
        let flags = parse_client_feature_flags(
            "windows-desktop-autotype, biometrics-sdk-ipc=false , fill-assist-targeting-rules=1, no-such-flag",
        );
        assert_eq!(
            flags,
            vec![
                ("windows-desktop-autotype".to_string(), true),
                ("biometrics-sdk-ipc".to_string(), false),
                ("fill-assist-targeting-rules".to_string(), true),
            ]
        );
    }

    #[test]
    fn supported_flag_list_contains_upstream_flags() {
        for flag in [
            "windows-desktop-autotype",
            "windows-desktop-autotype-ga",
            "biometrics-sdk-ipc",
            "fill-assist-targeting-rules",
        ] {
            assert!(SUPPORTED_CLIENT_FEATURE_FLAGS.contains(&flag));
        }
    }
}
