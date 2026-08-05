use std::sync::{LazyLock, RwLock};

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use worker::{D1Database, Env, Fetch, Method, Request, RequestInit, wasm_bindgen::JsValue};

use crate::error::AppError;

#[derive(Clone)]
struct PushConfig {
    installation_id: String,
    installation_key: String,
    relay_uri: String,
    identity_uri: String,
}

impl PushConfig {
    fn from_env(env: &Env) -> Result<Option<Self>, AppError> {
        if !env_bool(env, "PUSH_ENABLED", false) {
            return Ok(None);
        }
        let config = Self {
            installation_id: env_value(env, "PUSH_INSTALLATION_ID").ok_or_else(|| {
                AppError::BadRequest("PUSH_INSTALLATION_ID is required".to_string())
            })?,
            installation_key: env_value(env, "PUSH_INSTALLATION_KEY").ok_or_else(|| {
                AppError::BadRequest("PUSH_INSTALLATION_KEY is required".to_string())
            })?,
            relay_uri: env_value(env, "PUSH_RELAY_URI")
                .unwrap_or_else(|| "https://push.bitwarden.com".to_string()),
            identity_uri: env_value(env, "PUSH_IDENTITY_URI")
                .unwrap_or_else(|| "https://identity.bitwarden.com".to_string()),
        };
        validate_https_url(&config.relay_uri)?;
        validate_https_url(&config.identity_uri)?;
        Ok(Some(config))
    }
}

#[derive(Debug, Deserialize)]
struct AuthPushToken {
    access_token: String,
    expires_in: i64,
}

#[derive(Debug, Clone)]
struct CachedPushToken {
    installation_id: String,
    access_token: String,
    valid_until: i64,
}

static API_TOKEN: LazyLock<RwLock<Option<CachedPushToken>>> = LazyLock::new(|| RwLock::new(None));

fn env_value(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .ok()
        .map(|value| value.to_string())
        .or_else(|| env.var(name).ok().map(|value| value.to_string()))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_bool(env: &Env, name: &str, default: bool) -> bool {
    match env_value(env, name).as_deref().map(str::to_ascii_lowercase) {
        Some(value) if matches!(value.as_str(), "1" | "true" | "yes" | "on") => true,
        Some(value) if matches!(value.as_str(), "0" | "false" | "no" | "off") => false,
        _ => default,
    }
}

fn validate_https_url(value: &str) -> Result<(), AppError> {
    let url = url::Url::parse(value)
        .map_err(|_| AppError::BadRequest("Invalid push service URL".to_string()))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(AppError::BadRequest(
            "Push service URLs must use HTTPS".to_string(),
        ));
    }
    Ok(())
}

async fn get_auth_api_token(config: &PushConfig) -> Result<String, AppError> {
    let now = Utc::now().timestamp();
    if let Some(token) = API_TOKEN
        .read()
        .ok()
        .and_then(|token| token.as_ref().cloned())
        .filter(|token| token.installation_id == config.installation_id && token.valid_until > now)
    {
        return Ok(token.access_token);
    }

    let client_id = format!("installation.{}", config.installation_id);
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "client_credentials"),
            ("scope", "api.push"),
            ("client_id", client_id.as_str()),
            ("client_secret", config.installation_key.as_str()),
        ])
        .finish();
    let token_url = format!(
        "{}/connect/token",
        config.identity_uri.trim_end_matches('/')
    );
    let mut response = send_request(
        &token_url,
        Method::Post,
        Some(&body),
        "application/x-www-form-urlencoded",
        None,
    )
    .await?;
    let token: AuthPushToken = response.json().await?;
    let valid_until = now + (token.expires_in.max(0) / 2);
    if let Ok(mut cached) = API_TOKEN.write() {
        *cached = Some(CachedPushToken {
            installation_id: config.installation_id.clone(),
            access_token: token.access_token.clone(),
            valid_until,
        });
    }
    Ok(token.access_token)
}

async fn send_request(
    url: &str,
    method: Method,
    body: Option<&str>,
    content_type: &str,
    bearer: Option<&str>,
) -> Result<worker::Response, AppError> {
    let mut init = RequestInit::new();
    init.with_method(method);
    if let Some(body) = body {
        init.with_body(Some(JsValue::from_str(body)));
    }
    let mut request = Request::new_with_init(url, &init)?;
    let headers = request.headers_mut()?;
    headers.set("accept", "application/json")?;
    headers.set("content-type", content_type)?;
    if let Some(bearer) = bearer {
        headers.set("authorization", &format!("Bearer {bearer}"))?;
    }
    let response = Fetch::Request(request).send().await?;
    if !(200..300).contains(&response.status_code()) {
        return Err(AppError::BadRequest(format!(
            "Push relay request failed with status {}",
            response.status_code()
        )));
    }
    Ok(response)
}

async fn send_to_push_relay(env: &Env, data: Value) -> Result<(), AppError> {
    let Some(config) = PushConfig::from_env(env)? else {
        return Ok(());
    };
    let token = get_auth_api_token(&config).await?;
    let url = format!("{}/push/send", config.relay_uri.trim_end_matches('/'));
    send_request(
        &url,
        Method::Post,
        Some(&data.to_string()),
        "application/json",
        Some(&token),
    )
    .await?;
    Ok(())
}

async fn user_has_push_device(db: &D1Database, user_id: &str) -> Result<bool, AppError> {
    let result = db
        .prepare(
            "SELECT 1 AS present FROM devices
             WHERE user_id = ?1 AND push_uuid IS NOT NULL AND push_token IS NOT NULL LIMIT 1",
        )
        .bind(&[user_id.into()])?
        .first::<i64>(Some("present"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(result.is_some())
}

#[derive(Debug, Deserialize)]
struct ActingDevice {
    id: String,
    push_uuid: Option<String>,
}

async fn acting_device(
    db: &D1Database,
    user_id: &str,
    device_identifier: Option<&str>,
) -> Result<Option<ActingDevice>, AppError> {
    let Some(device_identifier) = device_identifier else {
        return Ok(None);
    };
    db.prepare(
        "SELECT id, push_uuid FROM devices
         WHERE user_id = ?1 AND (device_identifier = ?2 OR id = ?2) LIMIT 1",
    )
    .bind(&[user_id.into(), device_identifier.into()])?
    .first(None)
    .await
    .map_err(|_| AppError::Database)
}

pub async fn register_push_device(
    env: &Env,
    user_id: &str,
    device_identifier: &str,
    device_type: i32,
    push_token: &str,
    push_uuid: &str,
) -> Result<(), AppError> {
    let Some(config) = PushConfig::from_env(env)? else {
        return Ok(());
    };
    if !matches!(device_type, 0 | 1) || push_token.is_empty() {
        return Ok(());
    }
    let token = get_auth_api_token(&config).await?;
    let url = format!("{}/push/register", config.relay_uri.trim_end_matches('/'));
    let data = json!({
        "deviceId": push_uuid,
        "pushToken": push_token,
        "userId": user_id,
        "type": device_type,
        "identifier": device_identifier,
        "installationId": config.installation_id,
    });
    send_request(
        &url,
        Method::Post,
        Some(&data.to_string()),
        "application/json",
        Some(&token),
    )
    .await?;
    Ok(())
}

pub async fn unregister_push_device(env: &Env, push_uuid: Option<&str>) -> Result<(), AppError> {
    let (Some(config), Some(push_uuid)) = (PushConfig::from_env(env)?, push_uuid) else {
        return Ok(());
    };
    let token = get_auth_api_token(&config).await?;
    let url = format!(
        "{}/push/delete/{push_uuid}",
        config.relay_uri.trim_end_matches('/')
    );
    send_request(&url, Method::Post, None, "application/json", Some(&token)).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn push_vault_update(
    env: &Env,
    update_type: i32,
    user_id: &str,
    item_id: Option<&str>,
    revision_date: &str,
    acting_device_id: Option<&str>,
    payload_kind: &str,
) -> Result<(), AppError> {
    let Some(_config) = PushConfig::from_env(env)? else {
        return Ok(());
    };
    let db = crate::db::get_db(env)?;
    if !user_has_push_device(&db, user_id).await? {
        return Ok(());
    }
    let acting = acting_device(&db, user_id, acting_device_id).await?;
    let payload = match payload_kind {
        "cipher" => json!({
            "id": item_id,
            "userId": user_id,
            "organizationId": null,
            "collectionIds": null,
            "revisionDate": revision_date,
        }),
        "folder" | "send" => json!({
            "id": item_id,
            "userId": user_id,
            "revisionDate": revision_date,
        }),
        _ => json!({ "userId": user_id, "date": revision_date }),
    };
    send_to_push_relay(
        env,
        json!({
            "userId": user_id,
            "organizationId": null,
            "deviceId": acting.as_ref().and_then(|device| device.push_uuid.as_deref()),
            "identifier": acting.as_ref().map(|device| device.id.as_str()),
            "type": update_type,
            "payload": payload,
            "clientType": null,
            "installationId": null,
        }),
    )
    .await
}

pub async fn push_cipher_update(
    env: &Env,
    update_type: i32,
    user_id: &str,
    cipher_id: &str,
    revision_date: &str,
    acting_device_id: Option<&str>,
) -> Result<(), AppError> {
    push_vault_update(
        env,
        update_type,
        user_id,
        Some(cipher_id),
        revision_date,
        acting_device_id,
        "cipher",
    )
    .await
}

pub async fn push_folder_update(
    env: &Env,
    update_type: i32,
    user_id: &str,
    folder_id: &str,
    revision_date: &str,
    acting_device_id: Option<&str>,
) -> Result<(), AppError> {
    push_vault_update(
        env,
        update_type,
        user_id,
        Some(folder_id),
        revision_date,
        acting_device_id,
        "folder",
    )
    .await
}

pub async fn push_send_update(
    env: &Env,
    update_type: i32,
    user_id: &str,
    send_id: &str,
    revision_date: &str,
) -> Result<(), AppError> {
    push_vault_update(
        env,
        update_type,
        user_id,
        Some(send_id),
        revision_date,
        None,
        "send",
    )
    .await
}

pub async fn push_user_update(
    env: &Env,
    update_type: i32,
    user_id: &str,
    revision_date: &str,
    acting_device_id: Option<&str>,
) -> Result<(), AppError> {
    push_vault_update(
        env,
        update_type,
        user_id,
        None,
        revision_date,
        acting_device_id,
        "user",
    )
    .await
}

async fn push_auth_event(
    env: &Env,
    user_id: &str,
    auth_request_id: &str,
    update_type: i32,
) -> Result<(), AppError> {
    let Some(_config) = PushConfig::from_env(env)? else {
        return Ok(());
    };
    let db = crate::db::get_db(env)?;
    if !user_has_push_device(&db, user_id).await? {
        return Ok(());
    }
    send_to_push_relay(
        env,
        json!({
            "userId": user_id,
            "organizationId": null,
            "deviceId": null,
            "identifier": null,
            "type": update_type,
            "payload": { "userId": user_id, "id": auth_request_id },
            "clientType": null,
            "installationId": null,
        }),
    )
    .await
}

pub async fn push_auth_request(
    env: &Env,
    user_id: &str,
    auth_request_id: &str,
) -> Result<(), AppError> {
    push_auth_event(env, user_id, auth_request_id, 15).await
}

pub async fn push_auth_response(
    env: &Env,
    user_id: &str,
    auth_request_id: &str,
) -> Result<(), AppError> {
    push_auth_event(env, user_id, auth_request_id, 16).await
}

pub fn new_push_uuid() -> String {
    Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_service_requires_https() {
        assert!(validate_https_url("https://push.bitwarden.com").is_ok());
        assert!(validate_https_url("http://push.bitwarden.com").is_err());
        assert!(validate_https_url("not-a-url").is_err());
    }

    #[test]
    fn push_uuid_is_random_uuid() {
        let first = new_push_uuid();
        let second = new_push_uuid();
        assert_ne!(first, second);
        assert!(Uuid::parse_str(&first).is_ok());
    }
}
