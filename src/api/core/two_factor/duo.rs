use axum::{Json, extract::State, http::HeaderMap};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::Sha1;
use std::sync::Arc;
use worker::{D1Database, Env, Fetch, Method, Request};

use crate::{
    api::AppState,
    auth::Claims,
    db,
    db::models::two_factor,
    error::AppError,
    extensions::notify::{self, NotifyContext, NotifyEvent},
};

use super::PasswordOrOtpData;

const DISABLED_MESSAGE_DEFAULT: &str =
    "<To use the global Duo keys, please leave these fields untouched>";
const DUO_EXPIRE: i64 = 300;
const APP_EXPIRE: i64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DuoData {
    pub(crate) host: String,
    pub(crate) ik: String,
    pub(crate) sk: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableDuoData {
    host: String,
    client_secret: String,
    client_id: String,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

fn env_value(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .ok()
        .map(|value| value.to_string())
        .or_else(|| env.var(name).ok().map(|value| value.to_string()))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn use_iframe(env: &Env) -> bool {
    env_value(env, "DUO_USE_IFRAME").is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn global_duo_data(env: &Env) -> Option<DuoData> {
    Some(DuoData {
        host: env_value(env, "DUO_HOST")?,
        ik: env_value(env, "DUO_IKEY")?,
        sk: env_value(env, "DUO_SKEY")?,
    })
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && !host.contains('/')
        && !host.contains(':')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn hmac_sha1_hex(key: &str, value: &str) -> Result<String, AppError> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key.as_bytes()).map_err(|_| AppError::Internal)?;
    mac.update(value.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn mask(value: &str) -> String {
    let visible = value.chars().take(4).collect::<String>();
    format!("{visible}************")
}

fn obscure(data: &DuoData) -> DuoData {
    DuoData {
        host: mask(&data.host),
        ik: mask(&data.ik),
        sk: mask(&data.sk),
    }
}

async fn configured_data(
    db: &D1Database,
    env: &Env,
    user_id: &str,
) -> Result<Option<DuoData>, AppError> {
    match two_factor::get_external_two_factor(db, user_id, two_factor::TWO_FACTOR_PROVIDER_DUO)
        .await?
    {
        Some(data) if data.is_empty() => Ok(global_duo_data(env)),
        Some(data) => serde_json::from_str(&data)
            .map(Some)
            .map_err(|_| AppError::Internal),
        None => Ok(None),
    }
}

pub(crate) async fn configured_duo_data(
    db: &D1Database,
    env: &Env,
    user_id: &str,
) -> Result<DuoData, AppError> {
    configured_data(db, env, user_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Can't fetch Duo keys".to_string()))
}

async fn duo_api_check(data: &DuoData) -> Result<(), AppError> {
    if !valid_host(&data.host) {
        return Err(AppError::BadRequest("Invalid Duo API hostname".to_string()));
    }
    let path = "/auth/v2/check";
    let method = "GET";
    let date = Utc::now().to_rfc2822();
    let canonical = format!("{date}\n{method}\n{}\n{path}\n", data.host);
    let password = hmac_sha1_hex(&data.sk, &canonical)?;
    let mut request = Request::new(&format!("https://{}{path}", data.host), Method::Get)
        .map_err(|_| AppError::Internal)?;
    let headers = request.headers_mut().map_err(|_| AppError::Internal)?;
    headers
        .set(
            "Authorization",
            &format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{password}", data.ik))
            ),
        )
        .map_err(|_| AppError::Internal)?;
    headers.set("Date", &date).map_err(|_| AppError::Internal)?;
    headers
        .set("User-Agent", "warden-worker:Duo/1.0")
        .map_err(|_| AppError::Internal)?;
    let response = Fetch::Request(request)
        .send()
        .await
        .map_err(|_| AppError::BadRequest("Failed to validate Duo credentials".to_string()))?;
    if (200..300).contains(&response.status_code()) {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "Failed to validate Duo credentials".to_string(),
        ))
    }
}

fn response(enabled: bool, data: Option<DuoData>) -> Value {
    match data {
        Some(data) => json!({
            "enabled": enabled,
            "host": data.host,
            "clientSecret": data.sk,
            "clientId": data.ik,
            "object": "twoFactorDuo"
        }),
        None => json!({
            "enabled": enabled,
            "host": null,
            "clientSecret": null,
            "clientId": null,
            "object": "twoFactorDuo"
        }),
    }
}

#[worker::send]
pub async fn get_duo(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    data.validate(&db, &claims.sub).await?;
    let stored =
        two_factor::get_external_two_factor(&db, &claims.sub, two_factor::TWO_FACTOR_PROVIDER_DUO)
            .await?;
    let result = match stored {
        Some(value) if value.is_empty() => response(
            true,
            Some(DuoData {
                host: "<global_secret>".to_string(),
                ik: "<global_secret>".to_string(),
                sk: "<global_secret>".to_string(),
            }),
        ),
        Some(value) => {
            let data: DuoData = serde_json::from_str(&value).map_err(|_| AppError::Internal)?;
            response(true, Some(obscure(&data)))
        }
        None if global_duo_data(&state.env).is_some() => response(
            false,
            Some(DuoData {
                host: DISABLED_MESSAGE_DEFAULT.to_string(),
                ik: DISABLED_MESSAGE_DEFAULT.to_string(),
                sk: DISABLED_MESSAGE_DEFAULT.to_string(),
            }),
        ),
        None => response(false, None),
    };
    Ok(Json(result))
}

async fn activate_duo_impl(
    claims: Claims,
    state: Arc<AppState>,
    headers: HeaderMap,
    data: EnableDuoData,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    PasswordOrOtpData {
        master_password_hash: data.master_password_hash.clone(),
        otp: data.otp.clone(),
    }
    .validate(&db, &claims.sub)
    .await?;
    let fields_are_custom = [&data.host, &data.client_secret, &data.client_id]
        .iter()
        .all(|value| {
            let value = value.trim();
            !value.is_empty() && value != DISABLED_MESSAGE_DEFAULT && value != "<global_secret>"
        });
    let (stored, displayed) = if fields_are_custom {
        let custom = DuoData {
            host: data.host.trim().to_string(),
            ik: data.client_id.trim().to_string(),
            sk: data.client_secret.trim().to_string(),
        };
        duo_api_check(&custom).await?;
        (
            serde_json::to_string(&custom).map_err(|_| AppError::Internal)?,
            obscure(&custom),
        )
    } else {
        if global_duo_data(&state.env).is_none() {
            return Err(AppError::BadRequest(
                "Duo global credentials are not configured".to_string(),
            ));
        }
        (
            String::new(),
            DuoData {
                host: "<global_secret>".to_string(),
                ik: "<global_secret>".to_string(),
                sk: "<global_secret>".to_string(),
            },
        )
    };
    two_factor::upsert_external_two_factor(
        &db,
        &claims.sub,
        two_factor::TWO_FACTOR_PROVIDER_DUO,
        &stored,
    )
    .await?;
    let _ = two_factor::get_or_create_recovery_code(&db, &claims.sub).await?;
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorEnable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some("provider=duo".to_string()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );
    Ok(Json(response(true, Some(displayed))))
}

#[worker::send]
pub async fn activate_duo(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(data): Json<EnableDuoData>,
) -> Result<Json<Value>, AppError> {
    activate_duo_impl(claims, state, headers, data).await
}

#[worker::send]
pub async fn activate_duo_put(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(data): Json<EnableDuoData>,
) -> Result<Json<Value>, AppError> {
    activate_duo_impl(claims, state, headers, data).await
}

fn sign_duo_values(
    key: &str,
    email: &str,
    ikey: &str,
    prefix: &str,
    expire: i64,
) -> Result<String, AppError> {
    let value = format!("{email}|{ikey}|{expire}");
    let cookie = format!("{prefix}|{}", STANDARD.encode(value));
    Ok(format!("{cookie}|{}", hmac_sha1_hex(key, &cookie)?))
}

pub async fn generate_duo_signature(
    email: &str,
    user_id: &str,
    db: &D1Database,
    env: &Env,
) -> Result<(String, String), AppError> {
    let data = configured_duo_data(db, env, user_id).await?;
    let akey = env_value(env, "DUO_AKEY")
        .ok_or_else(|| AppError::BadRequest("DUO_AKEY is required for Duo login".to_string()))?;
    let now = Utc::now().timestamp();
    let duo = sign_duo_values(&data.sk, email, &data.ik, "TX", now + DUO_EXPIRE)?;
    let app = sign_duo_values(&akey, email, &data.ik, "APP", now + APP_EXPIRE)?;
    Ok((format!("{duo}:{app}"), data.host))
}

fn parse_duo_values(
    key: &str,
    value: &str,
    ikey: &str,
    prefix: &str,
    now: i64,
) -> Result<String, AppError> {
    let parts = value.split('|').collect::<Vec<_>>();
    if parts.len() != 3 || parts[0] != prefix {
        return Err(AppError::Unauthorized("Invalid Duo response".to_string()));
    }
    let expected = hmac_sha1_hex(key, &format!("{}|{}", parts[0], parts[1]))?;
    if !constant_time_eq::constant_time_eq(expected.as_bytes(), parts[2].as_bytes()) {
        return Err(AppError::Unauthorized("Invalid Duo signature".to_string()));
    }
    let decoded = STANDARD
        .decode(parts[1])
        .map_err(|_| AppError::Unauthorized("Invalid Duo response".to_string()))?;
    let decoded = String::from_utf8(decoded)
        .map_err(|_| AppError::Unauthorized("Invalid Duo response".to_string()))?;
    let fields = decoded.split('|').collect::<Vec<_>>();
    if fields.len() != 3 || fields[1] != ikey {
        return Err(AppError::Unauthorized("Invalid Duo response".to_string()));
    }
    let expiry = fields[2]
        .parse::<i64>()
        .map_err(|_| AppError::Unauthorized("Invalid Duo response".to_string()))?;
    if now >= expiry {
        return Err(AppError::Unauthorized("Expired Duo response".to_string()));
    }
    Ok(fields[0].to_string())
}

pub async fn validate_duo_login(
    email: &str,
    user_id: &str,
    response: &str,
    db: &D1Database,
    env: &Env,
) -> Result<(), AppError> {
    let (auth, app) = response
        .split_once(':')
        .ok_or_else(|| AppError::Unauthorized("Invalid Duo response".to_string()))?;
    let data = configured_data(db, env, user_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Duo is not configured".to_string()))?;
    let akey = env_value(env, "DUO_AKEY")
        .ok_or_else(|| AppError::Unauthorized("Duo is not configured".to_string()))?;
    let now = Utc::now().timestamp();
    let auth_user = parse_duo_values(&data.sk, auth, &data.ik, "AUTH", now)?;
    let app_user = parse_duo_values(&akey, app, &data.ik, "APP", now)?;
    if !constant_time_eq::constant_time_eq(auth_user.as_bytes(), app_user.as_bytes())
        || !constant_time_eq::constant_time_eq(auth_user.as_bytes(), email.as_bytes())
    {
        return Err(AppError::Unauthorized(
            "Error validating Duo authentication".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duo_cookie_round_trips() {
        let signed =
            sign_duo_values("secret", "user@example.com", "ikey", "AUTH", i64::MAX).unwrap();
        assert_eq!(
            parse_duo_values("secret", &signed, "ikey", "AUTH", 1).unwrap(),
            "user@example.com"
        );
    }

    #[test]
    fn duo_host_rejects_urls_and_paths() {
        assert!(valid_host("api-example.duosecurity.com"));
        assert!(!valid_host("https://api-example.duosecurity.com"));
        assert!(!valid_host("api-example.duosecurity.com/path"));
    }
}
