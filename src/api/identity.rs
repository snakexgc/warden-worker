use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::{
    Json,
    extract::{RawForm, State},
    response::IntoResponse,
};
use chrono::{Duration, Utc};
use constant_time_eq::constant_time_eq;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use semver::Version;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;
use worker::wasm_bindgen::JsValue;

use super::core::{sends, two_factor as two_factor_api};
use crate::api::AppState;
use crate::extensions::notify::{self, NotifyContext, NotifyEvent};
use crate::worker_runtime::background::BackgroundExecutor;
use crate::{
    auth::Claims,
    crypto::{self, password},
    db,
    db::models::{OrganizationApiKey, auth_request, two_factor, user::User},
    error::AppError,
    worker_runtime::{jwt, logging::targets, webauthn},
};

const LOGIN_RATE_LIMITER_BINDING: &str = "LOGIN_LIMITER";
const UNAUTHENTICATED_RATE_LIMITER_BINDING: &str = "UNAUTHENTICATED_LIMITER";

/// 后台更新设备信息
/// 将设备表的创建和更新操作放入后台执行，减少登录响应延迟
fn update_device_background(
    ctx: &BackgroundExecutor,
    env: worker::Env,
    user_id: String,
    device_identifier: String,
    device_name: Option<String>,
    device_type: Option<i32>,
) {
    ctx.wait_until(async move {
        log::debug!(
            target: targets::DB,
            "background device update started user_id={} device_id={}",
            user_id,
            device_identifier
        );

        let db = match db::get_db(&env) {
            Ok(db) => db,
            Err(e) => {
                log::warn!(
                    target: targets::DB,
                    "background device update failed: cannot get database user_id={} error={:?}",
                    user_id,
                    e
                );
                return;
            }
        };

        let now = Utc::now().to_rfc3339();

        match db
            .prepare(
                "INSERT INTO devices (id, user_id, device_identifier, device_name, device_type, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(user_id, device_identifier) DO UPDATE SET
                   updated_at = excluded.updated_at,
                   device_name = COALESCE(excluded.device_name, devices.device_name),
                   device_type = COALESCE(excluded.device_type, devices.device_type)",
            )
            .bind(&[
                Uuid::new_v4().to_string().into(),
                user_id.clone().into(),
                device_identifier.clone().into(),
                js_opt_string(device_name.clone()),
                js_opt_i64(device_type.map(|v| v as i64)),
                now.clone().into(),
                now.into(),
            ])
        {
            Ok(stmt) => {
                match stmt.run().await {
                    Ok(_) => {
                        log::info!(
                            target: targets::DB,
                            "background device update success user_id={} device_id={} device_name={:?}",
                            user_id,
                            device_identifier,
                            device_name
                        );
                    }
                    Err(e) => {
                        log::warn!(
                            target: targets::DB,
                            "background device update failed: database error user_id={} device_id={} error={:?}",
                            user_id,
                            device_identifier,
                            e
                        );
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    target: targets::DB,
                    "background device update failed: bind error user_id={} device_id={} error={:?}",
                    user_id,
                    device_identifier,
                    e
                );
            }
        }
    });
}

/// 同步写入（或新建）设备的设备级 refresh token，并刷新 updated_at。
/// 供登录/刷新时绑定设备使用；设备删除或登出（clear-token）后刷新流程即失效。
async fn upsert_device_refresh_token(
    db: &worker::D1Database,
    user_id: &str,
    device_identifier: &str,
    refresh_token: &str,
) -> Result<(), AppError> {
    let now = Utc::now().to_rfc3339();
    db.prepare(
        "INSERT INTO devices (id, user_id, device_identifier, created_at, updated_at, refresh_token)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(user_id, device_identifier) DO UPDATE SET
           updated_at = excluded.updated_at,
           refresh_token = excluded.refresh_token",
    )
    .bind(&[
        Uuid::new_v4().to_string().into(),
        user_id.into(),
        device_identifier.into(),
        now.clone().into(),
        now.into(),
        refresh_token.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

#[derive(Debug, Default)]
pub struct TokenRequest {
    grant_type: String,
    username: Option<String>,
    password: Option<String>, // This is the masterPasswordHash
    refresh_token: Option<String>,
    token: Option<String>,
    device_response: Option<String>,
    scope: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    send_id: Option<String>,
    password_hash_b64: Option<String>,
    device_identifier: Option<String>,
    device_name: Option<String>,
    device_type: Option<i32>,
    two_factor_token: Option<String>,
    two_factor_provider: Option<i32>,
    two_factor_remember: Option<i32>,
    auth_request: Option<String>,
    access_code: Option<String>,
}

#[derive(Debug, Clone)]
struct DuoChallengeData {
    client_id: Option<String>,
    device_identifier: Option<String>,
}

impl From<&TokenRequest> for DuoChallengeData {
    fn from(request: &TokenRequest) -> Self {
        Self {
            client_id: request.client_id.clone(),
            device_identifier: request.device_identifier.clone(),
        }
    }
}

fn normalize_form_key(key: &str) -> String {
    key.bytes()
        .filter(|byte| *byte != b'_')
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

fn parse_optional_i32(value: &str, field: &str) -> Result<Option<i32>, AppError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<i32>()
        .map(Some)
        .map_err(|_| AppError::BadRequest(format!("Invalid {field}")))
}

fn parse_truthy_i32(value: &str) -> Result<Option<i32>, AppError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.eq_ignore_ascii_case("true") || value == "1" {
        return Ok(Some(1));
    }
    if value.eq_ignore_ascii_case("false") || value == "0" {
        return Ok(Some(0));
    }
    parse_optional_i32(value, "twoFactorRemember")
}

fn parse_token_request(raw: &[u8]) -> Result<TokenRequest, AppError> {
    let mut request = TokenRequest::default();
    for (key, value) in url::form_urlencoded::parse(raw) {
        let value = value.into_owned();
        match normalize_form_key(&key).as_str() {
            "granttype" => request.grant_type = value,
            "username" => request.username = Some(value),
            "password" => request.password = Some(value),
            "refreshtoken" => request.refresh_token = Some(value),
            "token" => request.token = Some(value),
            "deviceresponse" => request.device_response = Some(value),
            "scope" => request.scope = Some(value),
            "clientid" => request.client_id = Some(value),
            "clientsecret" => request.client_secret = Some(value),
            "sendid" => request.send_id = Some(value),
            "passwordhashb64" => request.password_hash_b64 = Some(value),
            "deviceidentifier" | "deviceid" => request.device_identifier = Some(value),
            "devicename" => request.device_name = Some(value),
            "devicetype" => {
                let value = value.trim();
                request.device_type = if value.is_empty() {
                    None
                } else {
                    Some(value.parse::<i32>().unwrap_or(14))
                };
            }
            "twofactortoken" => request.two_factor_token = Some(value),
            "twofactorprovider" => {
                request.two_factor_provider = parse_optional_i32(&value, "twoFactorProvider")?
            }
            "twofactorremember" => request.two_factor_remember = parse_truthy_i32(&value)?,
            "authrequest" => request.auth_request = Some(value),
            "code" | "accesscode" => request.access_code = Some(value),
            _ => {}
        }
    }
    request.grant_type = request.grant_type.trim().to_string();
    if request.grant_type.is_empty() {
        return Err(AppError::BadRequest("Missing grant_type".to_string()));
    }
    Ok(request)
}

fn js_opt_string(v: Option<String>) -> JsValue {
    match v {
        Some(v) => JsValue::from_str(&v),
        None => JsValue::NULL,
    }
}

fn js_opt_i64(v: Option<i64>) -> JsValue {
    match v {
        Some(v) => JsValue::from_f64(v as f64),
        None => JsValue::NULL,
    }
}

fn normalize_kdf_for_response(
    kdf_type: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
) -> (Option<i32>, Option<i32>) {
    crypto::normalize_kdf_params(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)
}

fn effective_device_identifier(
    request_device: Option<String>,
    token_device: Option<String>,
) -> Option<String> {
    request_device
        .filter(|value| !value.trim().is_empty())
        .or(token_device)
}

fn standard_refresh_response(full_response: &Value) -> Value {
    json!({
        "access_token": full_response["access_token"],
        "expires_in": full_response["expires_in"],
        "refresh_token": full_response["refresh_token"],
        "scope": full_response["scope"],
        "token_type": full_response["token_type"]
    })
}

#[derive(Debug, Clone)]
struct WebAuthnPrfOptionPayload {
    encrypted_private_key: String,
    encrypted_user_key: String,
}

/// JWT issuer：优先使用配置的 DOMAIN，与 Vaultwarden 的 `iss = CONFIG.domain()` 对齐。
fn token_issuer(state: &Arc<AppState>) -> String {
    state
        .env
        .secret("DOMAIN")
        .ok()
        .and_then(|secret| secret.as_ref().as_string())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "warden-worker".to_string())
}

async fn generate_tokens_and_response(
    user: User,
    state: &Arc<AppState>,
    device_identifier: Option<String>,
    webauthn_prf_option: Option<&WebAuthnPrfOptionPayload>,
) -> Result<Value, AppError> {
    let now = Utc::now();
    let expires_in = Duration::hours(2);
    let exp = (now + expires_in).timestamp() as usize;

    let access_claims = Claims {
        sub: user.id.clone(),
        exp,
        nbf: now.timestamp() as usize,
        iss: token_issuer(state),
        premium: true,
        name: user.name.clone().unwrap_or_else(|| "User".to_string()),
        email: user.email.clone(),
        email_verified: true,
        amr: vec!["Application".into()],
        sstamp: user.security_stamp.clone(),
        device: device_identifier.clone(),
        devicetype: None,
        client_id: Some("undefined".to_string()),
        scope: Some(vec!["api".into(), "offline_access".into()]),
        token: None,
    };

    let jwt_keys = state.jwt_keys.clone();
    let access_token = encode(
        &Header::default(),
        &access_claims,
        &EncodingKey::from_secret(jwt_keys.access_secret.as_ref()),
    )?;

    // 设备级 refresh token：登录时同步写入 devices.refresh_token，
    // 设备删除/登出后刷新流程会因设备记录或 token 不匹配而失效（对齐 Vaultwarden RefreshJwtClaims.token）
    let device_refresh_token = match device_identifier.as_deref() {
        Some(device_identifier) => {
            let db = db::get_db(&state.env)?;
            let token = Uuid::new_v4().to_string();
            upsert_device_refresh_token(&db, &user.id, device_identifier, &token).await?;
            Some(token)
        }
        None => None,
    };

    let refresh_expires_in = Duration::days(30);
    let refresh_exp = (now + refresh_expires_in).timestamp() as usize;
    let refresh_claims = Claims {
        sub: user.id.clone(),
        exp: refresh_exp,
        nbf: now.timestamp() as usize,
        iss: token_issuer(state),
        premium: true,
        name: user.name.unwrap_or_else(|| "User".to_string()),
        email: user.email.clone(),
        email_verified: true,
        amr: vec!["Application".into()],
        sstamp: user.security_stamp.clone(),
        device: device_identifier,
        devicetype: None,
        client_id: Some("undefined".to_string()),
        scope: Some(vec!["api".into(), "offline_access".into()]),
        token: device_refresh_token,
    };
    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(jwt_keys.refresh_secret.as_ref()),
    )?;

    let (kdf_memory, kdf_parallelism) = normalize_kdf_for_response(
        user.kdf_type,
        user.kdf_iterations,
        user.kdf_memory,
        user.kdf_parallelism,
    );

    let mut user_decryption_options = json!({
        "HasMasterPassword": true,
        "MasterPasswordUnlock": {
            "Kdf": {
                "KdfType": user.kdf_type,
                "Iterations": user.kdf_iterations,
                "Memory": kdf_memory,
                "Parallelism": kdf_parallelism
            },
            "MasterKeyEncryptedUserKey": user.key,
            "MasterKeyWrappedUserKey": user.key,
            "Salt": user.email
        },
        "Object": "userDecryptionOptions"
    });

    if let Some(option) = webauthn_prf_option
        && let Some(obj) = user_decryption_options.as_object_mut()
    {
        obj.insert(
            "WebAuthnPrfOption".to_string(),
            json!({
                "EncryptedPrivateKey": option.encrypted_private_key,
                "EncryptedUserKey": option.encrypted_user_key
            }),
        );
    }

    Ok(json!({
        "ForcePasswordReset": false,
        "Kdf": user.kdf_type,
        "KdfIterations": user.kdf_iterations,
        "KdfMemory": kdf_memory,
        "KdfParallelism": kdf_parallelism,
        "Key": user.key,
        "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
        "PrivateKey": user.private_key,
        "ResetMasterPassword": false,
        "UserDecryptionOptions": user_decryption_options,
        "AccountKeys": {
            "publicKeyEncryptionKeyPair": {
                "wrappedPrivateKey": user.private_key,
                "publicKey": user.public_key,
                "Object": "publicKeyEncryptionKeyPair"
            },
            "Object": "privateKeys"
        },
        "access_token": access_token,
        "expires_in": expires_in.num_seconds(),
        "refresh_token": refresh_token,
        "scope": "api offline_access",
        "token_type": "Bearer"
    }))
}

async fn generate_api_key_tokens_response(
    user: User,
    state: &Arc<AppState>,
    device_identifier: String,
) -> Result<Value, AppError> {
    let now = Utc::now();
    let expires_in = Duration::hours(2);
    let claims = Claims {
        sub: user.id.clone(),
        exp: (now + expires_in).timestamp() as usize,
        nbf: now.timestamp() as usize,
        iss: token_issuer(state),
        premium: true,
        name: user.name.clone().unwrap_or_else(|| "User".to_string()),
        email: user.email.clone(),
        email_verified: user.email_verified,
        amr: vec!["Application".into()],
        sstamp: user.security_stamp.clone(),
        device: Some(device_identifier),
        devicetype: None,
        client_id: Some("api".to_string()),
        scope: Some(vec!["api".into()]),
        token: None,
    };
    let access_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_keys.access_secret.as_ref()),
    )?;
    let (kdf_memory, kdf_parallelism) = normalize_kdf_for_response(
        user.kdf_type,
        user.kdf_iterations,
        user.kdf_memory,
        user.kdf_parallelism,
    );

    Ok(json!({
        "access_token": access_token,
        "expires_in": expires_in.num_seconds(),
        "token_type": "Bearer",
        "Key": user.key,
        "PrivateKey": user.private_key,
        "Kdf": user.kdf_type,
        "KdfIterations": user.kdf_iterations,
        "KdfMemory": kdf_memory,
        "KdfParallelism": kdf_parallelism,
        "ResetMasterPassword": false,
        "ForcePasswordReset": false,
        "scope": "api",
        "AccountKeys": {
            "publicKeyEncryptionKeyPair": {
                "wrappedPrivateKey": user.private_key,
                "publicKey": user.public_key,
                "Object": "publicKeyEncryptionKeyPair"
            },
            "Object": "privateKeys"
        },
        "UserDecryptionOptions": {
            "HasMasterPassword": true,
            "MasterPasswordUnlock": {
                "Kdf": {
                    "KdfType": user.kdf_type,
                    "Iterations": user.kdf_iterations,
                    "Memory": kdf_memory,
                    "Parallelism": kdf_parallelism
                },
                "MasterKeyEncryptedUserKey": user.key,
                "MasterKeyWrappedUserKey": user.key,
                "Salt": user.email
            },
            "Object": "userDecryptionOptions"
        }
    }))
}

fn organization_api_key_issuer(state: &AppState) -> String {
    format!(
        "{}|api.organization",
        state.public_url("").trim_end_matches('/')
    )
}

async fn generate_organization_api_key_tokens_response(
    api_key: &OrganizationApiKey,
    state: &AppState,
) -> Result<Value, AppError> {
    let now = Utc::now();
    let expires_in = Duration::hours(1);
    let claims = crate::auth::OrgApiKeyClaims {
        nbf: now.timestamp() as usize,
        exp: (now + expires_in).timestamp() as usize,
        iss: organization_api_key_issuer(state),
        sub: api_key.id.clone(),
        client_id: format!("organization.{}", api_key.organization_id),
        client_sub: api_key.organization_id.clone(),
        scope: vec!["api.organization".to_string()],
    };
    let access_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_keys.access_secret.as_ref()),
    )?;

    Ok(json!({
        "access_token": access_token,
        "expires_in": expires_in.num_seconds(),
        "token_type": "Bearer",
        "scope": "api.organization"
    }))
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn verify_remember_token(
    token: &str,
    device_uuid: &str,
    user_uuid: &str,
    jwt_secret: &str,
) -> bool {
    match jwt::decode_2fa_remember(token, jwt_secret) {
        Ok(claims) => claims.sub == device_uuid && claims.user_uuid == user_uuid,
        Err(_) => false,
    }
}

async fn generate_remember_token_async(
    device_uuid: &str,
    user_uuid: &str,
    state: &Arc<AppState>,
) -> Result<String, AppError> {
    let jwt_keys = state.jwt_keys.clone();
    let claims = jwt::generate_2fa_remember_claims(device_uuid.to_string(), user_uuid.to_string());
    jwt::encode_2fa_remember(&claims, &jwt_keys.access_secret)
}

async fn verify_remember_token_async(
    token: &str,
    device_uuid: &str,
    user_uuid: &str,
    state: &Arc<AppState>,
) -> Result<bool, AppError> {
    let jwt_keys = state.jwt_keys.clone();
    Ok(verify_remember_token(
        token,
        device_uuid,
        user_uuid,
        &jwt_keys.access_secret,
    ))
}

fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=')
            && k.trim() == name
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

fn set_cookie(
    headers: &mut axum::http::HeaderMap,
    name: &str,
    value: &str,
    max_age_seconds: i64,
) -> Result<(), AppError> {
    let cookie = format!(
        "{name}={value}; Max-Age={max_age_seconds}; Path=/; HttpOnly; Secure; SameSite=Lax",
    );
    headers.append(
        header::SET_COOKIE,
        cookie.parse().map_err(|_| AppError::Internal)?,
    );
    Ok(())
}

pub(crate) fn client_ip_from_headers(headers: &HeaderMap) -> String {
    crate::auth::client_ip_from_headers(headers)
}

pub(crate) async fn enforce_login_rate_limit_for(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    namespace: &str,
    username: &str,
) -> Result<(), AppError> {
    let limiter = match state.env.rate_limiter(LOGIN_RATE_LIMITER_BINDING) {
        Ok(l) => l,
        Err(_) => return Ok(()),
    };
    let ip = client_ip_from_headers(headers);
    let key = format!("{namespace}:{}:{}", ip, username.trim().to_lowercase());
    let outcome = limiter.limit(key).await.map_err(|_| AppError::Internal)?;
    if !outcome.success {
        return Err(AppError::TooManyRequests(
            "Too many login attempts".to_string(),
        ));
    }
    Ok(())
}

pub(crate) async fn enforce_unauthenticated_rate_limit(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    let limiter = match state.env.rate_limiter(UNAUTHENTICATED_RATE_LIMITER_BINDING) {
        Ok(limiter) => limiter,
        Err(_) => return Ok(()),
    };
    let key = format!("unauthenticated:{}", client_ip_from_headers(headers));
    let outcome = limiter.limit(key).await.map_err(|_| AppError::Internal)?;
    if !outcome.success {
        return Err(AppError::TooManyRequests(
            "Too many unauthenticated requests".to_string(),
        ));
    }
    Ok(())
}

async fn enforce_login_rate_limit(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    username: &str,
) -> Result<(), AppError> {
    enforce_login_rate_limit_for(state, headers, "login", username).await
}

async fn get_email_2fa_display_info(
    providers: &[i32],
    user_id: &str,
    state: &Arc<AppState>,
) -> Option<(String, String)> {
    if !providers.contains(&two_factor::TWO_FACTOR_PROVIDER_EMAIL) {
        return None;
    }

    let db = match db::get_db(&state.env) {
        Ok(db) => db,
        Err(_) => return None,
    };

    let (_, data) = match two_factor::get_email_2fa(&db, user_id).await {
        Ok(Some((enabled, data))) if enabled => (enabled, data),
        _ => return None,
    };

    let email_data = match two_factor::EmailTokenData::from_json(&data) {
        Ok(d) => d,
        Err(_) => return None,
    };

    let obscured = obscure_email(&email_data.email);
    Some((obscured, email_data.email))
}

fn client_needs_legacy_email_2fa_send(headers: &HeaderMap) -> bool {
    let Some(version) = headers
        .get("bitwarden-client-version")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return true;
    };
    Version::parse(version)
        .map(|version| version < Version::new(2025, 5, 0))
        .unwrap_or(true)
}

async fn maybe_send_legacy_email_2fa(
    providers: &[i32],
    user_id: &str,
    headers: &HeaderMap,
    state: &Arc<AppState>,
    db: &worker::D1Database,
) -> Result<(), AppError> {
    if providers == [two_factor::TWO_FACTOR_PROVIDER_EMAIL]
        && client_needs_legacy_email_2fa_send(headers)
    {
        two_factor_api::issue_email_login_token(db, state, user_id).await?;
    }
    Ok(())
}

fn obscure_email(email: &str) -> String {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return "***".to_string();
    }
    let name = parts[0];
    let domain = parts[1];

    let obscured_name = if name.len() <= 2 {
        "*".repeat(name.len())
    } else {
        format!("{}***", &name[..2])
    };

    format!("{}@{}", obscured_name, domain)
}

fn invalid_grant_response(error_description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "invalid_grant",
            "error_description": error_description,
        })),
    )
        .into_response()
}

async fn load_user_by_id(db: &worker::D1Database, user_id: &str) -> Result<User, AppError> {
    db.prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first::<Value>(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))
        .and_then(|value| serde_json::from_value(value).map_err(|_| AppError::Internal))
}

async fn two_factor_required_response(
    providers: &[i32],
    user_id: &str,
    email_2fa_data: Option<(String, String)>,
    headers: &HeaderMap,
    state: &Arc<AppState>,
    db: &worker::D1Database,
    duo: &DuoChallengeData,
) -> Response {
    let mut response_providers: Vec<String> = Vec::new();
    let mut providers2 = serde_json::Map::new();
    for &p in providers {
        if p == two_factor::TWO_FACTOR_PROVIDER_EMAIL {
            response_providers.push(p.to_string());
            if let Some((ref email, _)) = email_2fa_data {
                providers2.insert(
                    p.to_string(),
                    json!({
                        "Email": email
                    }),
                );
            } else {
                providers2.insert(p.to_string(), Value::Null);
            }
        } else if p == two_factor::TWO_FACTOR_PROVIDER_DUO {
            if let Ok(user) = load_user_by_id(db, user_id).await {
                let challenge = if two_factor_api::duo::use_iframe(&state.env) {
                    two_factor_api::duo::generate_duo_signature(
                        &user.email,
                        user_id,
                        db,
                        &state.env,
                    )
                    .await
                    .map(|(signature, host)| json!({ "Host": host, "Signature": signature }))
                } else {
                    match (duo.client_id.as_deref(), duo.device_identifier.as_deref()) {
                        (Some(client_id), Some(device_identifier)) => {
                            two_factor_api::duo_oidc::get_duo_auth_url(
                                &user.email,
                                user_id,
                                client_id,
                                device_identifier,
                                db,
                                &state.env,
                            )
                            .await
                            .map(|auth_url| json!({ "AuthUrl": auth_url }))
                        }
                        _ => Err(AppError::BadRequest(
                            "Duo OIDC requires client and device identifiers".to_string(),
                        )),
                    }
                };
                if let Ok(challenge) = challenge {
                    response_providers.push(p.to_string());
                    providers2.insert(p.to_string(), challenge);
                }
            }
        } else if p == two_factor::TWO_FACTOR_PROVIDER_YUBIKEY {
            if let Ok(Some(data)) = two_factor::get_external_two_factor(db, user_id, p).await
                && let Ok(metadata) =
                    serde_json::from_str::<two_factor_api::yubikey::YubikeyMetadata>(&data)
            {
                response_providers.push(p.to_string());
                providers2.insert(p.to_string(), json!({ "Nfc": metadata.nfc }));
            }
        } else if p == two_factor::TWO_FACTOR_PROVIDER_WEBAUTHN {
            if webauthn::is_webauthn_2fa_supported(headers) {
                let rp_id = webauthn::rp_id_from_headers(headers);
                let origin = webauthn::origin_from_headers(headers);
                if let Ok(Some(challenge)) = webauthn::issue_login_challenge(
                    db,
                    user_id,
                    &rp_id,
                    &origin,
                    webauthn::WEBAUTHN_USE_2FA,
                )
                .await
                {
                    response_providers.push(p.to_string());
                    providers2.insert(p.to_string(), challenge);
                }
            }
        } else {
            response_providers.push(p.to_string());
            providers2.insert(p.to_string(), Value::Null);
        }
    }
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "TwoFactorProviders": response_providers,
            "TwoFactorProviders2": providers2,
            "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
            "error": "invalid_grant",
            "error_description": "Two factor required."
        })),
    )
        .into_response()
}

async fn invalid_two_factor_response(
    providers: &[i32],
    user_id: &str,
    headers: &HeaderMap,
    state: &Arc<AppState>,
    db: &worker::D1Database,
    duo: &DuoChallengeData,
) -> Response {
    let mut response_providers: Vec<String> = Vec::new();
    let email_2fa_data = get_email_2fa_display_info(providers, user_id, state).await;

    let mut providers2 = serde_json::Map::new();
    for &p in providers {
        if p == two_factor::TWO_FACTOR_PROVIDER_EMAIL {
            response_providers.push(p.to_string());
            if let Some((ref email, _)) = email_2fa_data {
                providers2.insert(
                    p.to_string(),
                    json!({
                        "Email": email
                    }),
                );
            } else {
                providers2.insert(p.to_string(), Value::Null);
            }
        } else if p == two_factor::TWO_FACTOR_PROVIDER_DUO {
            if let Ok(user) = load_user_by_id(db, user_id).await {
                let challenge = if two_factor_api::duo::use_iframe(&state.env) {
                    two_factor_api::duo::generate_duo_signature(
                        &user.email,
                        user_id,
                        db,
                        &state.env,
                    )
                    .await
                    .map(|(signature, host)| json!({ "Host": host, "Signature": signature }))
                } else {
                    match (duo.client_id.as_deref(), duo.device_identifier.as_deref()) {
                        (Some(client_id), Some(device_identifier)) => {
                            two_factor_api::duo_oidc::get_duo_auth_url(
                                &user.email,
                                user_id,
                                client_id,
                                device_identifier,
                                db,
                                &state.env,
                            )
                            .await
                            .map(|auth_url| json!({ "AuthUrl": auth_url }))
                        }
                        _ => Err(AppError::BadRequest(
                            "Duo OIDC requires client and device identifiers".to_string(),
                        )),
                    }
                };
                if let Ok(challenge) = challenge {
                    response_providers.push(p.to_string());
                    providers2.insert(p.to_string(), challenge);
                }
            }
        } else if p == two_factor::TWO_FACTOR_PROVIDER_YUBIKEY {
            if let Ok(Some(data)) = two_factor::get_external_two_factor(db, user_id, p).await
                && let Ok(metadata) =
                    serde_json::from_str::<two_factor_api::yubikey::YubikeyMetadata>(&data)
            {
                response_providers.push(p.to_string());
                providers2.insert(p.to_string(), json!({ "Nfc": metadata.nfc }));
            }
        } else if p == two_factor::TWO_FACTOR_PROVIDER_WEBAUTHN {
            if webauthn::is_webauthn_2fa_supported(headers) {
                let rp_id = webauthn::rp_id_from_headers(headers);
                let origin = webauthn::origin_from_headers(headers);
                if let Ok(Some(challenge)) = webauthn::issue_login_challenge(
                    db,
                    user_id,
                    &rp_id,
                    &origin,
                    webauthn::WEBAUTHN_USE_2FA,
                )
                .await
                {
                    response_providers.push(p.to_string());
                    providers2.insert(p.to_string(), challenge);
                }
            }
        } else {
            response_providers.push(p.to_string());
            providers2.insert(p.to_string(), Value::Null);
        }
    }
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "TwoFactorProviders": response_providers,
            "TwoFactorProviders2": providers2,
            "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
            "error": "invalid_grant",
            "error_description": "Invalid two factor token."
        })),
    )
        .into_response()
}

#[worker::send]
pub async fn token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RawForm(raw_form): RawForm,
) -> Result<Response, AppError> {
    let payload = parse_token_request(&raw_form)?;
    let duo_challenge = DuoChallengeData::from(&payload);
    let db = db::get_db(&state.env)?;
    match payload.grant_type.as_str() {
        "send_access" => {
            if payload.client_id.as_deref().is_none_or(str::is_empty) {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_request",
                        "error_description": "client_id cannot be blank"
                    })),
                )
                    .into_response());
            }
            let Some(access_id) = payload.send_id.as_deref().filter(|value| !value.is_empty())
            else {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_request",
                        "error_description": "send_id cannot be blank"
                    })),
                )
                    .into_response());
            };

            sends::issue_send_access_token(&state, &headers, access_id, payload.password_hash_b64)
                .await
        }
        "client_credentials" => {
            let client_id = payload
                .client_id
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| AppError::BadRequest("client_id cannot be blank".to_string()))?;
            let client_secret = payload
                .client_secret
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| AppError::BadRequest("client_secret cannot be blank".to_string()))?;
            let device_identifier = payload
                .device_identifier
                .clone()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    AppError::BadRequest("device_identifier cannot be blank".to_string())
                })?;
            let device_name = payload
                .device_name
                .clone()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| AppError::BadRequest("device_name cannot be blank".to_string()))?;
            let device_type = payload
                .device_type
                .ok_or_else(|| AppError::BadRequest("device_type cannot be blank".to_string()))?;

            enforce_login_rate_limit(&state, &headers, client_id).await?;
            if payload.scope.as_deref() == Some("api.organization") {
                let organization_id = client_id
                    .strip_prefix("organization.")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| AppError::BadRequest("Malformed client_id".to_string()))?;
                let api_key: OrganizationApiKey = db
                    .prepare(
                        "SELECT id, organization_id, type, api_key, revision_date FROM organization_api_key WHERE organization_id = ?1",
                    )
                    .bind(&[organization_id.into()])?
                    .first::<Value>(None)
                    .await
                    .map_err(|_| AppError::Database)?
                    .ok_or_else(|| AppError::BadRequest("Invalid client_id".to_string()))
                    .and_then(|value| {
                        serde_json::from_value(value).map_err(|_| AppError::Internal)
                    })?;
                if !constant_time_eq(api_key.api_key.as_bytes(), client_secret.as_bytes()) {
                    return Err(AppError::BadRequest("Incorrect client_secret".to_string()));
                }
                let response =
                    generate_organization_api_key_tokens_response(&api_key, &state).await?;
                return Ok(Json(response).into_response());
            }
            if payload.scope.as_deref() != Some("api") {
                return Err(AppError::BadRequest("Scope not supported".to_string()));
            }
            let user_id = client_id
                .strip_prefix("user.")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| AppError::BadRequest("Malformed client_id".to_string()))?;
            let user: User = db
                .prepare("SELECT * FROM users WHERE id = ?1")
                .bind(&[user_id.into()])?
                .first::<Value>(None)
                .await
                .map_err(|_| AppError::Database)?
                .ok_or_else(|| AppError::Unauthorized("Invalid client_id".to_string()))
                .and_then(|value| serde_json::from_value(value).map_err(|_| AppError::Internal))?;
            let stored_api_key = user.api_key.as_deref().unwrap_or_default();
            if !constant_time_eq(stored_api_key.as_bytes(), client_secret.as_bytes()) {
                notify::notify_background(
                    &state.ctx,
                    state.env.clone(),
                    NotifyEvent::LoginFailed,
                    NotifyContext {
                        user_id: Some(user.id),
                        user_email: Some(user.email),
                        device_identifier: Some(device_identifier),
                        device_name: Some(device_name),
                        device_type: Some(device_type),
                        meta: notify::extract_request_meta(&headers),
                        ..Default::default()
                    },
                );
                return Err(AppError::BadRequest("Incorrect client_secret".to_string()));
            }

            let user_id = user.id.clone();
            let user_email = user.email.clone();
            let response =
                generate_api_key_tokens_response(user, &state, device_identifier.clone()).await?;
            update_device_background(
                &state.ctx,
                state.env.clone(),
                user_id.clone(),
                device_identifier.clone(),
                Some(device_name.clone()),
                Some(device_type),
            );
            notify::notify_background(
                &state.ctx,
                state.env.clone(),
                NotifyEvent::Login,
                NotifyContext {
                    user_id: Some(user_id),
                    user_email: Some(user_email),
                    device_identifier: Some(device_identifier),
                    device_name: Some(device_name),
                    device_type: Some(device_type),
                    meta: notify::extract_request_meta(&headers),
                    ..Default::default()
                },
            );
            Ok(Json(response).into_response())
        }
        "password" => {
            if payload.client_id.as_deref().is_none_or(str::is_empty) {
                return Err(AppError::BadRequest(
                    "client_id cannot be blank".to_string(),
                ));
            }
            if payload.scope.as_deref() != Some("api offline_access") {
                return Err(AppError::BadRequest("Scope not supported".to_string()));
            }
            if payload
                .device_identifier
                .as_deref()
                .is_none_or(str::is_empty)
            {
                return Err(AppError::BadRequest(
                    "device_identifier cannot be blank".to_string(),
                ));
            }
            if payload.device_name.as_deref().is_none_or(str::is_empty) {
                return Err(AppError::BadRequest(
                    "device_name cannot be blank".to_string(),
                ));
            }
            if payload.device_type.is_none() {
                return Err(AppError::BadRequest(
                    "device_type cannot be blank".to_string(),
                ));
            }
            let username = crate::auth::normalize_email(
                &payload
                    .username
                    .ok_or_else(|| AppError::BadRequest("Missing username".to_string()))?,
            );
            if username.is_empty() {
                return Err(AppError::BadRequest("Missing username".to_string()));
            }
            enforce_login_rate_limit(&state, &headers, &username).await?;
            let password_hash = if payload.auth_request.is_some() {
                payload.password.unwrap_or_default()
            } else {
                payload
                    .password
                    .ok_or_else(|| AppError::BadRequest("Missing password".to_string()))?
            };

            let user_val: Value = match db
                .prepare("SELECT * FROM users WHERE email = ?1")
                .bind(&[username.clone().into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Database)?
            {
                Some(v) => v,
                None => {
                    notify::notify_background(
                        &state.ctx,
                        state.env.clone(),
                        NotifyEvent::LoginFailed,
                        NotifyContext {
                            user_email: Some(username.clone()),
                            device_identifier: payload.device_identifier.clone(),
                            device_name: payload.device_name.clone(),
                            device_type: payload.device_type,
                            meta: notify::extract_request_meta(&headers),
                            ..Default::default()
                        },
                    );
                    return Ok(invalid_grant_response("Invalid username or password"));
                }
            };
            let user: User = serde_json::from_value(user_val).map_err(|_| AppError::Internal)?;

            // If this is an auth-request login (trusted device), skip master password check
            // and verify the auth-request access code instead.
            if let Some(auth_request_id) = payload.auth_request.as_deref() {
                auth_request::purge_expired(&db).await?;

                let ar_row: Option<Value> = db
                    .prepare("SELECT * FROM auth_requests WHERE id = ?1 AND user_id = ?2 LIMIT 1")
                    .bind(&[auth_request_id.into(), user.id.clone().into()])?
                    .first(None)
                    .await
                    .map_err(|_| AppError::Database)?;
                let ar_row = ar_row
                    .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;

                // Must be approved
                let approved = ar_row
                    .get("approved")
                    .and_then(|v| {
                        if v.is_null() {
                            None
                        } else if let Some(b) = v.as_bool() {
                            Some(b)
                        } else {
                            v.as_i64().map(|i| i != 0)
                        }
                    })
                    .unwrap_or(false);
                if !approved {
                    return Ok(invalid_grant_response("Invalid username or password"));
                }

                let already_authenticated = ar_row
                    .get("authentication_date")
                    .and_then(|v| v.as_str())
                    .is_some();
                if already_authenticated {
                    return Ok(invalid_grant_response("Invalid username or password"));
                }

                let request_device_identifier = ar_row
                    .get("request_device_identifier")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let request_device_type = ar_row
                    .get("device_type")
                    .and_then(|v| v.as_i64())
                    .map(|v| v as i32)
                    .unwrap_or(14);
                let request_ip = ar_row
                    .get("request_ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();

                let payload_device_identifier = payload
                    .device_identifier
                    .as_deref()
                    .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;
                if payload_device_identifier != request_device_identifier {
                    return Ok(invalid_grant_response("Invalid username or password"));
                }

                let payload_device_type = payload
                    .device_type
                    .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;
                if payload_device_type != request_device_type {
                    return Ok(invalid_grant_response("Invalid username or password"));
                }

                let current_ip = client_ip_from_headers(&headers);
                if current_ip != request_ip {
                    return Ok(invalid_grant_response("Invalid username or password"));
                }

                // Verify access code
                let stored_hash = ar_row
                    .get("access_code_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();

                let access_code = payload.access_code.as_deref().unwrap_or(&password_hash);
                let candidate_hash = sha256_hex(access_code);
                if !constant_time_eq(stored_hash.as_bytes(), candidate_hash.as_bytes()) {
                    return Ok(invalid_grant_response("Invalid username or password"));
                }

                db.prepare(
                    "UPDATE auth_requests
                     SET authentication_date = ?1
                     WHERE id = ?2 AND user_id = ?3 AND authentication_date IS NULL",
                )
                .bind(&[
                    Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                        .into(),
                    auth_request_id.into(),
                    user.id.clone().into(),
                ])?
                .run()
                .await
                .map_err(|_| AppError::Database)?;

                db.prepare("DELETE FROM auth_requests WHERE id = ?1 AND user_id = ?2")
                    .bind(&[auth_request_id.into(), user.id.clone().into()])?
                    .run()
                    .await
                    .map_err(|_| AppError::Database)?;

                // Auth-request login bypasses 2FA and remember-device flow
                let user_id = user.id.clone();
                let device_identifier = payload.device_identifier.clone();
                let device_name = payload.device_name.clone();
                let device_type = payload.device_type;

                let response =
                    generate_tokens_and_response(user, &state, device_identifier.clone(), None)
                        .await?;

                if let Some(device_id) = device_identifier {
                    update_device_background(
                        &state.ctx,
                        state.env.clone(),
                        user_id,
                        device_id,
                        device_name,
                        device_type,
                    );
                }

                return Ok(Json(response).into_response());
            }

            let password_valid =
                password::verify_user_password(&db, &user.id, &password_hash).await?;

            if !password_valid {
                notify::notify_background(
                    &state.ctx,
                    state.env.clone(),
                    NotifyEvent::LoginFailed,
                    NotifyContext {
                        user_id: Some(user.id.clone()),
                        user_email: Some(user.email.clone()),
                        device_identifier: payload.device_identifier.clone(),
                        device_name: payload.device_name.clone(),
                        device_type: payload.device_type,
                        meta: notify::extract_request_meta(&headers),
                        ..Default::default()
                    },
                );
                return Err(AppError::Unauthorized("Invalid credentials".to_string()));
            }

            let authenticator_enabled = two_factor::is_authenticator_enabled(&db, &user.id).await?;
            let email_2fa_enabled = two_factor::is_email_2fa_enabled(&db, &user.id).await?;
            let email_2fa_usable =
                email_2fa_enabled && notify::is_email_webhook_configured(&state.env);
            let duo_enabled = two_factor::is_external_two_factor_enabled(
                &db,
                &user.id,
                two_factor::TWO_FACTOR_PROVIDER_DUO,
            )
            .await?;
            let duo_usable = if !duo_enabled {
                false
            } else if two_factor_api::duo::use_iframe(&state.env) {
                two_factor_api::duo::generate_duo_signature(&user.email, &user.id, &db, &state.env)
                    .await
                    .is_ok()
            } else {
                two_factor_api::duo_oidc::is_configured(&state.env)
                    && two_factor_api::duo::configured_duo_data(&db, &state.env, &user.id)
                        .await
                        .is_ok()
            };
            let yubikey_enabled = two_factor::is_external_two_factor_enabled(
                &db,
                &user.id,
                two_factor::TWO_FACTOR_PROVIDER_YUBIKEY,
            )
            .await?;
            let yubikey_usable =
                yubikey_enabled && two_factor_api::yubikey::is_configured(&state.env);
            let webauthn_enabled = webauthn::is_webauthn_enabled(&db, &user.id).await?;
            let webauthn_usable = webauthn_enabled && webauthn::is_webauthn_2fa_supported(&headers);
            let two_factor_enabled = authenticator_enabled
                || email_2fa_enabled
                || duo_enabled
                || yubikey_enabled
                || webauthn_enabled;

            let mut providers: Vec<i32> = Vec::new();
            if authenticator_enabled {
                providers.push(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR);
            }
            if email_2fa_usable {
                providers.push(two_factor::TWO_FACTOR_PROVIDER_EMAIL);
            }
            if duo_usable {
                providers.push(two_factor::TWO_FACTOR_PROVIDER_DUO);
            }
            if yubikey_usable {
                providers.push(two_factor::TWO_FACTOR_PROVIDER_YUBIKEY);
            }
            if webauthn_usable {
                providers.push(two_factor::TWO_FACTOR_PROVIDER_WEBAUTHN);
            }
            if two_factor_enabled && providers.is_empty() {
                return Ok(invalid_grant_response(
                    "No enabled and usable two factor providers are available for this account",
                ));
            }
            if two_factor_enabled
                && crate::db::models::two_factor_incomplete::TwoFactorIncomplete::time_limit_minutes(
                    &state.env,
                ) > 0
                && notify::is_webhook_configured(&state.env)
                && let (Some(device_id), Some(device_name), Some(device_type)) = (
                    payload.device_identifier.as_deref(),
                    payload.device_name.as_deref(),
                    payload.device_type,
                )
            {
                crate::db::models::two_factor_incomplete::TwoFactorIncomplete::mark_incomplete(
                    &db,
                    &user.id,
                    device_id,
                    device_name,
                    device_type,
                    &client_ip_from_headers(&headers),
                )
                .await?;
            }
            // 注意：Recovery Code (type=8) 不在这里添加，因为它不是常规的2FA方式
            // 它只在登录验证时作为一种特殊的恢复选项处理

            let mut remember_token_to_return: Option<String> = None;
            if two_factor_enabled {
                let wants_remember = payload.two_factor_remember.unwrap_or(0) == 1;
                let provider = payload.two_factor_provider;
                let token = payload.two_factor_token.clone();

                if provider.is_none() && token.is_none() {
                    let Some(device_identifier) = payload.device_identifier.as_deref() else {
                        maybe_send_legacy_email_2fa(&providers, &user.id, &headers, &state, &db)
                            .await?;
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers,
                            &user.id,
                            email_data,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    };
                    let cookie_token = get_cookie(&headers, "twoFactorRemember")
                        .or_else(|| get_cookie(&headers, "TwoFactorRemember"));
                    let Some(cookie_token) = cookie_token.as_deref() else {
                        maybe_send_legacy_email_2fa(&providers, &user.id, &headers, &state, &db)
                            .await?;
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers,
                            &user.id,
                            email_data,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    };

                    let valid = verify_remember_token_async(
                        cookie_token.trim(),
                        device_identifier,
                        &user.id,
                        &state,
                    )
                    .await?;
                    if !valid {
                        maybe_send_legacy_email_2fa(&providers, &user.id, &headers, &state, &db)
                            .await?;
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers,
                            &user.id,
                            email_data,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    }

                    if wants_remember && payload.device_identifier.is_some() {
                        remember_token_to_return = Some(
                            generate_remember_token_async(
                                payload.device_identifier.as_deref().unwrap(),
                                &user.id,
                                &state,
                            )
                            .await?,
                        );
                    }
                } else if provider == Some(5) {
                    let Some(device_identifier) = payload.device_identifier.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers,
                            &user.id,
                            email_data,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    };
                    let Some(token) = token.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers,
                            &user.id,
                            email_data,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    };

                    let valid = verify_remember_token_async(
                        token.trim(),
                        device_identifier,
                        &user.id,
                        &state,
                    )
                    .await?;
                    if !valid {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers,
                            &user.id,
                            email_data,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    }
                } else if provider == Some(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR)
                    && authenticator_enabled
                {
                    let Some(token) = token.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers,
                            &user.id,
                            email_data,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    };

                    let secret_enc = two_factor::get_authenticator_secret_enc(&db, &user.id)
                        .await?
                        .ok_or_else(|| AppError::Internal)?;
                    let secret_encoded = two_factor::decrypt_secret_with_key(
                        &state.two_factor_key,
                        &user.id,
                        &secret_enc,
                    )?;
                    if !two_factor::consume_totp_code(&db, &user.id, &secret_encoded, token).await?
                    {
                        notify::notify_background(
                            &state.ctx,
                            state.env.clone(),
                            NotifyEvent::LoginFailed,
                            NotifyContext {
                                user_id: Some(user.id.clone()),
                                user_email: Some(user.email.clone()),
                                detail: Some("2FA Authenticator Verification Failed".to_string()),
                                device_identifier: payload.device_identifier.clone(),
                                device_name: payload.device_name.clone(),
                                device_type: payload.device_type,
                                meta: notify::extract_request_meta(&headers),
                                ..Default::default()
                            },
                        );
                        return Ok(invalid_two_factor_response(
                            &providers,
                            &user.id,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    }

                    if wants_remember && payload.device_identifier.is_some() {
                        remember_token_to_return = Some(
                            generate_remember_token_async(
                                payload.device_identifier.as_deref().unwrap(),
                                &user.id,
                                &state,
                            )
                            .await?,
                        );
                    }
                } else if provider == Some(two_factor::TWO_FACTOR_PROVIDER_EMAIL)
                    && email_2fa_usable
                {
                    let Some(token) = token.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers,
                            &user.id,
                            email_data,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    };

                    let (_, data) = two_factor::get_email_2fa(&db, &user.id)
                        .await?
                        .ok_or_else(|| AppError::Internal)?;
                    let mut email_data = two_factor::EmailTokenData::from_json(&data)?;

                    let Some(issued_token) = email_data.last_token.clone() else {
                        log::warn!(
                            target: targets::AUTH,
                            "email 2fa login failed: no token available user_id={}",
                            user.id
                        );
                        return Ok(invalid_two_factor_response(
                            &providers,
                            &user.id,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    };

                    // 首先验证token是否匹配（常量时间比较）
                    if !constant_time_eq(token.as_bytes(), issued_token.as_bytes()) {
                        // 验证失败，增加尝试次数
                        email_data.add_attempt();
                        if email_data.attempts >= 3 {
                            email_data.reset_token();
                        }

                        let now = Utc::now().to_rfc3339();
                        let _ = two_factor::upsert_email_2fa(
                            &db,
                            &user.id,
                            two_factor::TWO_FACTOR_PROVIDER_EMAIL,
                            true,
                            &email_data.to_json(),
                            &now,
                        )
                        .await;

                        log::warn!(
                            target: targets::AUTH,
                            "email 2fa login failed: invalid token user_id={} attempts={}",
                            user.id,
                            email_data.attempts
                        );

                        notify::notify_background(
                            &state.ctx,
                            state.env.clone(),
                            NotifyEvent::LoginFailed,
                            NotifyContext {
                                user_id: Some(user.id.clone()),
                                user_email: Some(user.email.clone()),
                                detail: Some("2FA Email Verification Failed".to_string()),
                                device_identifier: payload.device_identifier.clone(),
                                device_name: payload.device_name.clone(),
                                device_type: payload.device_type,
                                meta: notify::extract_request_meta(&headers),
                                ..Default::default()
                            },
                        );
                        return Ok(invalid_two_factor_response(
                            &providers,
                            &user.id,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    }

                    // token验证成功，先重置token
                    email_data.reset_token();
                    let now = Utc::now().to_rfc3339();
                    two_factor::upsert_email_2fa(
                        &db,
                        &user.id,
                        two_factor::TWO_FACTOR_PROVIDER_EMAIL,
                        true,
                        &email_data.to_json(),
                        &now,
                    )
                    .await?;

                    // 最后检查token是否过期（参考vaultwarden实现）
                    if two_factor::is_token_expired(email_data.token_sent, 600) {
                        log::warn!(
                            target: targets::AUTH,
                            "email 2fa login failed: token expired user_id={}",
                            user.id
                        );
                        return Ok(invalid_two_factor_response(
                            &providers,
                            &user.id,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    }

                    log::info!(
                        target: targets::AUTH,
                        "email 2fa login success user_id={}",
                        user.id
                    );

                    if wants_remember && payload.device_identifier.is_some() {
                        remember_token_to_return = Some(
                            generate_remember_token_async(
                                payload.device_identifier.as_deref().unwrap(),
                                &user.id,
                                &state,
                            )
                            .await?,
                        );
                    }
                } else if provider == Some(two_factor::TWO_FACTOR_PROVIDER_DUO) && duo_usable {
                    let Some(token) = token.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers,
                            &user.id,
                            email_data,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    };
                    let duo_result = if two_factor_api::duo::use_iframe(&state.env) {
                        two_factor_api::duo::validate_duo_login(
                            &user.email,
                            &user.id,
                            token,
                            &db,
                            &state.env,
                        )
                        .await
                    } else {
                        match (
                            duo_challenge.client_id.as_deref(),
                            duo_challenge.device_identifier.as_deref(),
                        ) {
                            (Some(client_id), Some(device_identifier)) => {
                                two_factor_api::duo_oidc::validate_duo_login(
                                    &user.email,
                                    &user.id,
                                    token,
                                    client_id,
                                    device_identifier,
                                    &db,
                                    &state.env,
                                )
                                .await
                            }
                            _ => Err(AppError::Unauthorized(
                                "Duo OIDC requires client and device identifiers".to_string(),
                            )),
                        }
                    };
                    if duo_result.is_err() {
                        notify::notify_background(
                            &state.ctx,
                            state.env.clone(),
                            NotifyEvent::LoginFailed,
                            NotifyContext {
                                user_id: Some(user.id.clone()),
                                user_email: Some(user.email.clone()),
                                detail: Some("2FA Duo Verification Failed".to_string()),
                                device_identifier: payload.device_identifier.clone(),
                                device_name: payload.device_name.clone(),
                                device_type: payload.device_type,
                                meta: notify::extract_request_meta(&headers),
                                ..Default::default()
                            },
                        );
                        return Ok(invalid_two_factor_response(
                            &providers,
                            &user.id,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    }
                    if wants_remember && payload.device_identifier.is_some() {
                        remember_token_to_return = Some(
                            generate_remember_token_async(
                                payload.device_identifier.as_deref().unwrap(),
                                &user.id,
                                &state,
                            )
                            .await?,
                        );
                    }
                } else if provider == Some(two_factor::TWO_FACTOR_PROVIDER_YUBIKEY)
                    && yubikey_usable
                {
                    let Some(token) = token.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers,
                            &user.id,
                            email_data,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    };
                    let data = two_factor::get_external_two_factor(
                        &db,
                        &user.id,
                        two_factor::TWO_FACTOR_PROVIDER_YUBIKEY,
                    )
                    .await?
                    .ok_or_else(|| AppError::Internal)?;
                    if two_factor_api::yubikey::validate_yubikey_login(&state.env, token, &data)
                        .await
                        .is_err()
                    {
                        notify::notify_background(
                            &state.ctx,
                            state.env.clone(),
                            NotifyEvent::LoginFailed,
                            NotifyContext {
                                user_id: Some(user.id.clone()),
                                user_email: Some(user.email.clone()),
                                detail: Some("2FA YubiKey Verification Failed".to_string()),
                                device_identifier: payload.device_identifier.clone(),
                                device_name: payload.device_name.clone(),
                                device_type: payload.device_type,
                                meta: notify::extract_request_meta(&headers),
                                ..Default::default()
                            },
                        );
                        return Ok(invalid_two_factor_response(
                            &providers,
                            &user.id,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    }
                    if wants_remember && payload.device_identifier.is_some() {
                        remember_token_to_return = Some(
                            generate_remember_token_async(
                                payload.device_identifier.as_deref().unwrap(),
                                &user.id,
                                &state,
                            )
                            .await?,
                        );
                    }
                } else if provider == Some(two_factor::TWO_FACTOR_PROVIDER_RECOVERY_CODE) {
                    let Some(token) = token.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers,
                            &user.id,
                            email_data,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    };

                    // 验证恢复码
                    let recovery_valid =
                        two_factor::verify_recovery_code(&db, &user.id, token).await?;
                    if !recovery_valid {
                        log::warn!(
                            target: targets::AUTH,
                            "recovery code login failed: invalid code user_id={}",
                            user.id
                        );

                        notify::notify_background(
                            &state.ctx,
                            state.env.clone(),
                            NotifyEvent::LoginFailed,
                            NotifyContext {
                                user_id: Some(user.id.clone()),
                                user_email: Some(user.email.clone()),
                                detail: Some("2FA Recovery Code Verification Failed".to_string()),
                                device_identifier: payload.device_identifier.clone(),
                                device_name: payload.device_name.clone(),
                                device_type: payload.device_type,
                                meta: notify::extract_request_meta(&headers),
                                ..Default::default()
                            },
                        );
                        return Ok(invalid_two_factor_response(
                            &providers,
                            &user.id,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    }

                    // 恢复码验证成功，删除所有2FA并清除恢复码
                    log::info!(
                        target: targets::AUTH,
                        "recovery code login success: removing all 2fa user_id={}",
                        user.id
                    );

                    two_factor::delete_all_two_factors(&db, &user.id).await?;
                    two_factor::clear_recovery_code(&db, &user.id).await?;

                    // 发送恢复通知
                    notify::notify_background(
                        &state.ctx,
                        state.env.clone(),
                        NotifyEvent::TwoFactorRecover,
                        NotifyContext {
                            user_id: Some(user.id.clone()),
                            user_email: Some(user.email.clone()),
                            device_identifier: payload.device_identifier.clone(),
                            device_name: payload.device_name.clone(),
                            device_type: payload.device_type,
                            meta: notify::extract_request_meta(&headers),
                            ..Default::default()
                        },
                    );
                } else if provider == Some(two_factor::TWO_FACTOR_PROVIDER_WEBAUTHN)
                    && webauthn_usable
                {
                    let Some(token) = token.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers,
                            &user.id,
                            email_data,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    };

                    if webauthn::verify_login_assertion(
                        &db,
                        &user.id,
                        token,
                        webauthn::WEBAUTHN_USE_2FA,
                    )
                    .await
                    .is_err()
                    {
                        notify::notify_background(
                            &state.ctx,
                            state.env.clone(),
                            NotifyEvent::LoginFailed,
                            NotifyContext {
                                user_id: Some(user.id.clone()),
                                user_email: Some(user.email.clone()),
                                detail: Some("2FA WebAuthn Verification Failed".to_string()),
                                device_identifier: payload.device_identifier.clone(),
                                device_name: payload.device_name.clone(),
                                device_type: payload.device_type,
                                meta: notify::extract_request_meta(&headers),
                                ..Default::default()
                            },
                        );
                        return Ok(invalid_two_factor_response(
                            &providers,
                            &user.id,
                            &headers,
                            &state,
                            &db,
                            &duo_challenge,
                        )
                        .await);
                    }

                    if wants_remember && payload.device_identifier.is_some() {
                        remember_token_to_return = Some(
                            generate_remember_token_async(
                                payload.device_identifier.as_deref().unwrap(),
                                &user.id,
                                &state,
                            )
                            .await?,
                        );
                    }
                } else {
                    let email_data = get_email_2fa_display_info(&providers, &user.id, &state).await;
                    return Ok(two_factor_required_response(
                        &providers,
                        &user.id,
                        email_data,
                        &headers,
                        &state,
                        &db,
                        &duo_challenge,
                    )
                    .await);
                }
            }

            if two_factor_enabled && let Some(device_id) = payload.device_identifier.as_deref() {
                crate::db::models::two_factor_incomplete::TwoFactorIncomplete::mark_complete(
                    &db, &user.id, device_id,
                )
                .await?;
            }

            let user_id = user.id.clone();
            let user_email_for_notify = Some(user.email.clone());
            let device_identifier = payload.device_identifier.clone();
            let device_name = payload.device_name.clone();
            let device_type = payload.device_type;
            // 登录成功：写入 UserLoggedIn 服务端审计事件（对齐 Vaultwarden）
            super::core::events::log_event(
                &db,
                &state.env,
                1000,
                Some(&user.id),
                None,
                None,
                &user.id,
            )
            .await?;
            log::info!(
                target: targets::AUTH,
                "token login device id={:?} type={:?} name={:?} 2fa_provider={:?} remember={:?}",
                device_identifier,
                device_type,
                device_name,
                payload.two_factor_provider,
                payload.two_factor_remember
            );

            let mut response =
                generate_tokens_and_response(user, &state, device_identifier.clone(), None).await?;
            let remember_token_to_set = remember_token_to_return.clone();

            // 后台异步更新设备信息，减少登录响应延迟
            if let Some(device_identifier) = device_identifier.clone() {
                log::debug!(
                    target: targets::AUTH,
                    "scheduling background device update user_id={} device_id={}",
                    user_id,
                    device_identifier
                );
                update_device_background(
                    &state.ctx,
                    state.env.clone(),
                    user_id.clone(),
                    device_identifier,
                    device_name.clone(),
                    device_type,
                );
            }

            if let Some(token) = remember_token_to_return
                && let Some(obj) = response.as_object_mut()
            {
                obj.insert("TwoFactorToken".to_string(), Value::String(token));
            }

            let access_token_to_set = response
                .get("access_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let refresh_token_to_set = response
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let mut resp = Json(response).into_response();
            if let Some(token) = remember_token_to_set {
                set_cookie(
                    resp.headers_mut(),
                    "twoFactorRemember",
                    &token,
                    Duration::days(30).num_seconds(),
                )?;
                set_cookie(
                    resp.headers_mut(),
                    "TwoFactorRemember",
                    &token,
                    Duration::days(30).num_seconds(),
                )?;
            }
            if let Some(v) = access_token_to_set.as_deref() {
                set_cookie(
                    resp.headers_mut(),
                    "bw_access_token",
                    v,
                    Duration::hours(2).num_seconds(),
                )?;
            }
            if let Some(v) = refresh_token_to_set.as_deref() {
                set_cookie(
                    resp.headers_mut(),
                    "bw_refresh_token",
                    v,
                    Duration::days(30).num_seconds(),
                )?;
            }

            notify::notify_background(
                &state.ctx,
                state.env.clone(),
                NotifyEvent::Login,
                NotifyContext {
                    user_id: Some(user_id),
                    user_email: user_email_for_notify,
                    device_identifier,
                    device_name,
                    device_type,
                    meta: notify::extract_request_meta(&headers),
                    ..Default::default()
                },
            );
            Ok(resp)
        }
        "refresh_token" => {
            let Some(refresh_token) = payload
                .refresh_token
                .or_else(|| get_cookie(&headers, "bw_refresh_token"))
            else {
                return Ok(invalid_grant_response("Missing refresh_token"));
            };

            let jwt_keys = state.jwt_keys.clone();
            let token_data = match decode::<Claims>(
                &refresh_token,
                &DecodingKey::from_secret(jwt_keys.refresh_secret.as_ref()),
                &Validation::default(),
            ) {
                Ok(data) => data,
                Err(_) => {
                    return Ok((
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_grant",
                            "error_description": "Invalid refresh token"
                        })),
                    )
                        .into_response());
                }
            };

            let refresh_claims = token_data.claims;
            let effective_device_identifier = effective_device_identifier(
                payload.device_identifier.clone(),
                refresh_claims.device.clone(),
            );
            let user_id = refresh_claims.sub;
            let user: Value = match db
                .prepare("SELECT * FROM users WHERE id = ?1")
                .bind(&[user_id.into()])?
                .first(None)
                .await
            {
                Ok(Some(v)) => v,
                _ => {
                    return Ok((
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_grant",
                            "error_description": "Invalid user"
                        })),
                    )
                        .into_response());
                }
            };
            let user: User = match serde_json::from_value(user) {
                Ok(u) => u,
                Err(_) => {
                    return Ok((
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_grant",
                            "error_description": "Invalid user"
                        })),
                    )
                        .into_response());
                }
            };

            let stamp = &refresh_claims.sstamp;

            if stamp != &user.security_stamp {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_grant",
                        "error_description": "Invalid security stamp"
                    })),
                )
                    .into_response());
            }

            // 设备级刷新校验：refresh token 绑定设备记录，设备删除/登出（clear-token）后刷新立即失效
            if let (Some(device_identifier), Some(expected_token)) = (
                effective_device_identifier.as_deref(),
                refresh_claims.token.as_deref(),
            ) {
                let device: Option<Value> = db
                    .prepare(
                        "SELECT refresh_token FROM devices
                         WHERE user_id = ?1 AND device_identifier = ?2",
                    )
                    .bind(&[user.id.clone().into(), device_identifier.into()])?
                    .first(None)
                    .await
                    .map_err(|_| AppError::Database)?;
                let device_token = device
                    .as_ref()
                    .and_then(|row| row.get("refresh_token"))
                    .and_then(Value::as_str);
                if device_token != Some(expected_token) {
                    return Ok(invalid_grant_response("Device is no longer available"));
                }
            }

            let full_response = generate_tokens_and_response(
                user.clone(),
                &state,
                effective_device_identifier.clone(),
                None,
            )
            .await?;
            let response = standard_refresh_response(&full_response);
            let mut resp = Json(response.clone()).into_response();
            if let Some(v) = response.get("access_token").and_then(|v| v.as_str()) {
                set_cookie(
                    resp.headers_mut(),
                    "bw_access_token",
                    v,
                    Duration::hours(2).num_seconds(),
                )?;
            }
            if let Some(v) = response.get("refresh_token").and_then(|v| v.as_str()) {
                set_cookie(
                    resp.headers_mut(),
                    "bw_refresh_token",
                    v,
                    Duration::days(30).num_seconds(),
                )?;
            }

            if let Some(device_identifier) = effective_device_identifier.clone() {
                update_device_background(
                    &state.ctx,
                    state.env.clone(),
                    user.id.clone(),
                    device_identifier,
                    payload.device_name.clone(),
                    payload.device_type,
                );
            }

            notify::notify_background(
                &state.ctx,
                state.env.clone(),
                NotifyEvent::TokenRefresh,
                NotifyContext {
                    user_id: Some(user.id.clone()),
                    user_email: Some(user.email.clone()),
                    device_identifier: effective_device_identifier,
                    device_name: payload.device_name.clone(),
                    device_type: payload.device_type,
                    meta: notify::extract_request_meta(&headers),
                    ..Default::default()
                },
            );

            Ok(resp)
        }
        "webauthn" => {
            let challenge_token = payload
                .token
                .ok_or_else(|| AppError::BadRequest("Missing token".to_string()))?;
            let device_response = payload
                .device_response
                .ok_or_else(|| AppError::BadRequest("Missing deviceResponse".to_string()))?;
            log::info!(
                target: targets::AUTH,
                "identity token webauthn start device_identifier={:?} device_name={:?} device_type={:?}",
                payload.device_identifier,
                payload.device_name,
                payload.device_type
            );
            let jwt_keys = state.jwt_keys.clone();
            let login_result = webauthn::verify_passwordless_login_assertion(
                &db,
                &challenge_token,
                &device_response,
                &jwt_keys.access_secret,
            )
            .await
            .map_err(|e| match e {
                AppError::BadRequest(msg) | AppError::Unauthorized(msg) => {
                    AppError::Unauthorized(msg)
                }
                other => other,
            })?;
            let user_id = login_result.user_id.clone();
            log::info!(
                target: targets::AUTH,
                "identity token webauthn verified user_id={} has_enc_user={} has_enc_priv={}",
                user_id,
                login_result
                    .encrypted_user_key
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .is_some(),
                login_result
                    .encrypted_private_key
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .is_some()
            );

            let user: Value = db
                .prepare("SELECT * FROM users WHERE id = ?1")
                .bind(&[user_id.clone().into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Unauthorized("Invalid WebAuthn credentials".to_string()))?
                .ok_or_else(|| {
                    AppError::Unauthorized("Invalid WebAuthn credentials".to_string())
                })?;
            let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

            let device_identifier = payload.device_identifier.clone();
            let device_name = payload.device_name.clone();
            let device_type = payload.device_type;

            let webauthn_prf_option = match (
                login_result.encrypted_private_key.as_deref(),
                login_result.encrypted_user_key.as_deref(),
            ) {
                (Some(encrypted_private_key), Some(encrypted_user_key))
                    if !encrypted_private_key.trim().is_empty()
                        && !encrypted_user_key.trim().is_empty() =>
                {
                    Some(WebAuthnPrfOptionPayload {
                        encrypted_private_key: encrypted_private_key.to_string(),
                        encrypted_user_key: encrypted_user_key.to_string(),
                    })
                }
                _ => None,
            };

            log::info!(
                target: targets::AUTH,
                "identity token webauthn response user_id={} include_prf_option={}",
                user_id,
                webauthn_prf_option.is_some()
            );

            let user_email = user.email.clone();
            let response = generate_tokens_and_response(
                user,
                &state,
                device_identifier.clone(),
                webauthn_prf_option.as_ref(),
            )
            .await?;

            if let Some(device_identifier) = device_identifier.as_deref() {
                let now = chrono::Utc::now().to_rfc3339();
                if let Ok(stmt) = db
                    .prepare(
                        "INSERT INTO devices (id, user_id, device_identifier, device_name, device_type, remember_token_hash, created_at, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                         ON CONFLICT(user_id, device_identifier) DO UPDATE SET
                           updated_at = excluded.updated_at,
                           device_name = excluded.device_name,
                           device_type = excluded.device_type,
                           remember_token_hash = COALESCE(excluded.remember_token_hash, devices.remember_token_hash)",
                    )
                    .bind(&[
                        Uuid::new_v4().to_string().into(),
                        user_id.clone().into(),
                        device_identifier.into(),
                        device_name.clone().into(),
                        device_type.map(f64::from).into(),
                        Option::<String>::None.into(),
                        now.clone().into(),
                        now.clone().into(),
                    ])
                {
                    let _ = stmt.run().await;
                }
            }

            let access_token_to_set = response
                .get("access_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let refresh_token_to_set = response
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let mut resp = Json(response).into_response();
            if let Some(v) = access_token_to_set.as_deref() {
                set_cookie(
                    resp.headers_mut(),
                    "bw_access_token",
                    v,
                    Duration::hours(2).num_seconds(),
                )?;
            }
            if let Some(v) = refresh_token_to_set.as_deref() {
                set_cookie(
                    resp.headers_mut(),
                    "bw_refresh_token",
                    v,
                    Duration::days(30).num_seconds(),
                )?;
            }

            // Send WebAuthn login notification
            notify::notify_background(
                &state.ctx,
                state.env.clone(),
                notify::NotifyEvent::WebAuthnLogin,
                notify::NotifyContext {
                    user_id: Some(user_id.clone()),
                    user_email: Some(user_email),
                    device_identifier: payload.device_identifier.clone(),
                    device_name: payload.device_name.clone(),
                    device_type: payload.device_type,
                    meta: notify::extract_request_meta(&headers),
                    ..Default::default()
                },
            );

            Ok(resp)
        }
        _ => Err(AppError::BadRequest("Unsupported grant_type".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        client_needs_legacy_email_2fa_send, effective_device_identifier, parse_token_request,
        standard_refresh_response,
    };
    use axum::http::{HeaderMap, HeaderValue};
    use serde_json::json;

    #[test]
    fn token_form_accepts_case_insensitive_compact_aliases() {
        let request = parse_token_request(
            b"GrAnTtYpE=password&CLIENTID=mobile&deviceidentifier=device-1&DEVICENAME=phone&DEVICETYPE=iOS&twofactortoken=123456&twofactorprovider=1&twofactorremember=true",
        )
        .unwrap();
        assert_eq!(request.grant_type, "password");
        assert_eq!(request.client_id.as_deref(), Some("mobile"));
        assert_eq!(request.device_identifier.as_deref(), Some("device-1"));
        assert_eq!(request.device_name.as_deref(), Some("phone"));
        assert_eq!(request.device_type, Some(14));
        assert_eq!(request.two_factor_token.as_deref(), Some("123456"));
        assert_eq!(request.two_factor_provider, Some(1));
        assert_eq!(request.two_factor_remember, Some(1));
    }

    #[test]
    fn token_form_accepts_underscored_refresh_aliases() {
        let request = parse_token_request(
            b"grant_type=refresh_token&refresh_token=refresh&client_id=web&device_identifier=device-2",
        )
        .unwrap();
        assert_eq!(request.grant_type, "refresh_token");
        assert_eq!(request.refresh_token.as_deref(), Some("refresh"));
        assert_eq!(request.client_id.as_deref(), Some("web"));
        assert_eq!(request.device_identifier.as_deref(), Some("device-2"));
    }

    #[test]
    fn refresh_inherits_device_and_returns_only_standard_fields() {
        assert_eq!(
            effective_device_identifier(None, Some("claim-device".to_string())).as_deref(),
            Some("claim-device")
        );
        let response = standard_refresh_response(&json!({
            "access_token": "access",
            "expires_in": 7200,
            "refresh_token": "refresh",
            "scope": "api offline_access",
            "token_type": "Bearer",
            "Key": "must-not-leak"
        }));
        assert_eq!(response.as_object().unwrap().len(), 5);
        assert!(response.get("Key").is_none());
    }

    #[test]
    fn legacy_email_2fa_send_version_boundary() {
        let mut headers = HeaderMap::new();
        assert!(client_needs_legacy_email_2fa_send(&headers));
        headers.insert(
            "bitwarden-client-version",
            HeaderValue::from_static("2025.4.9"),
        );
        assert!(client_needs_legacy_email_2fa_send(&headers));
        headers.insert(
            "bitwarden-client-version",
            HeaderValue::from_static("2025.5.0"),
        );
        assert!(!client_needs_legacy_email_2fa_send(&headers));
        headers.insert(
            "bitwarden-client-version",
            HeaderValue::from_static("2026.6.1"),
        );
        assert!(!client_needs_legacy_email_2fa_send(&headers));
    }
}
