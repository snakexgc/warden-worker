use axum::{extract::State, Json};
use axum::http::HeaderMap;
use chrono::Utc;
use constant_time_eq::constant_time_eq;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::logging::targets;
use crate::notify::{self, EmailType, NotifyContext, NotifyEvent};
use crate::router::AppState;
use crate::two_factor::{self, EmailTokenData};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableAuthenticatorRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableAuthenticatorRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOrOtpData {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

impl PasswordOrOtpData {
    async fn validate(&self, db: &worker::D1Database, user_id: &str) -> Result<(), AppError> {
        match (&self.master_password_hash, &self.otp) {
            (Some(master_password_hash), None) => {
                // 查询用户的密码哈希和salt
                let result: Option<serde_json::Value> = db
                    .prepare("SELECT master_password_hash, password_salt FROM users WHERE id = ?1")
                    .bind(&[user_id.into()])?
                    .first(None)
                    .await
                    .map_err(|_| AppError::Database)?;

                let Some(row) = result else {
                    log::warn!(
                        target: targets::AUTH,
                        "PasswordOrOtpData.validate: user not found user_id={}",
                        user_id
                    );
                    return Err(AppError::NotFound("User not found".to_string()));
                };

                let stored_hash = row.get("master_password_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let password_salt = row.get("password_salt")
                    .and_then(|v| v.as_str());

                // 调试日志：记录哈希长度（不记录实际哈希值）
                log::debug!(
                    target: targets::AUTH,
                    "PasswordOrOtpData.validate: comparing hashes user_id={} stored_len={} provided_len={} has_salt={}",
                    user_id,
                    stored_hash.len(),
                    master_password_hash.len(),
                    password_salt.is_some()
                );

                // 根据是否有salt选择验证方式
                let password_valid = if let Some(salt) = password_salt {
                    // 使用PBKDF2验证
                    crate::crypto::verify_password(master_password_hash, salt, stored_hash).await
                } else {
                    // 直接比较哈希值
                    constant_time_eq(stored_hash.as_bytes(), master_password_hash.as_bytes())
                };

                if !password_valid {
                    log::warn!(
                        target: targets::AUTH,
                        "PasswordOrOtpData.validate: password mismatch user_id={}",
                        user_id
                    );
                    return Err(AppError::Unauthorized("Invalid credentials".to_string()));
                }
                Ok(())
            }
            (None, Some(_)) => Err(AppError::BadRequest(
                "OTP validation is not supported".to_string(),
            )),
            _ => {
                log::warn!(
                    target: targets::AUTH,
                    "PasswordOrOtpData.validate: no validation provided user_id={}",
                    user_id
                );
                Err(AppError::BadRequest("No validation provided".to_string()))
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum NumberOrString {
    Number(i64),
    String(String),
}

impl NumberOrString {
    fn into_string(self) -> String {
        match self {
            NumberOrString::Number(n) => n.to_string(),
            NumberOrString::String(s) => s,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableAuthenticatorData {
    key: String,
    token: NumberOrString,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableAuthenticatorData {
    key: String,
    master_password_hash: String,
    #[serde(rename = "type")]
    r#type: NumberOrString,
}

#[worker::send]
pub async fn two_factor_status(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    
    let mut providers: Vec<i32> = Vec::new();
    
    let authenticator_enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?;
    if authenticator_enabled {
        providers.push(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR);
    }
    
    let email_enabled = two_factor::is_email_2fa_enabled(&db, &claims.sub).await?;
    if email_enabled {
        providers.push(two_factor::TWO_FACTOR_PROVIDER_EMAIL);
    }
    
    let enabled = !providers.is_empty();
    
    Ok(Json(json!({
        "enabled": enabled,
        "providers": providers
    })))
}

#[worker::send]
pub async fn authenticator_request(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now().to_rfc3339();

    let user_email: Option<String> = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(Some("email"))
        .await
        .map_err(|_| AppError::Database)?;
    let user_email = user_email.ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let secret_encoded = two_factor::generate_totp_secret_base32_20();
    let two_factor_key_b64 = state.env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
    let secret_enc = two_factor::encrypt_secret_with_optional_key(
        two_factor_key_b64.as_deref(),
        &claims.sub,
        &secret_encoded,
    )?;

    two_factor::upsert_authenticator_secret(&db, &claims.sub, secret_enc, false, &now).await?;

    let issuer = state.env
        .var("TWO_FACTOR_ISSUER")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_else(|| "Warden Worker".to_string());
    let issuer = issuer.replace(':', "");
    let account = user_email.replace(':', "");
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret_encoded.clone())
            .to_bytes()
            .map_err(|_| AppError::Internal)?,
        Some(issuer.clone()),
        account.clone(),
    )
    .map_err(|_| AppError::Internal)?;
    let otpauth = totp.get_url();
    let qr_base64 = totp.get_qr_base64().map_err(|_| AppError::Internal)?;

    Ok(Json(json!({
        "secret": secret_encoded,
        "otpauth": otpauth,
        "qrBase64": qr_base64
    })))
}

#[worker::send]
pub async fn get_authenticator(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    payload.validate(&db, &claims.sub).await?;

    let enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?;
    let key = if enabled {
        let secret_enc = two_factor::get_authenticator_secret_enc(&db, &claims.sub)
            .await?
            .ok_or_else(|| AppError::Internal)?;
        let two_factor_key_b64 = state.env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
        two_factor::decrypt_secret_with_optional_key(two_factor_key_b64.as_deref(), &claims.sub, &secret_enc)?
    } else {
        two_factor::generate_totp_secret_base32_20()
    };

    Ok(Json(json!({
        "enabled": enabled,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

#[worker::send]
pub async fn activate_authenticator(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<EnableAuthenticatorData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    PasswordOrOtpData {
        master_password_hash: payload.master_password_hash.clone(),
        otp: payload.otp.clone(),
    }
    .validate(&db, &claims.sub)
    .await?;

    let key = payload.key.trim().to_uppercase();
    let key_bytes = Secret::Encoded(key.clone())
        .to_bytes()
        .map_err(|_| AppError::BadRequest("Invalid totp secret".to_string()))?;
    if key_bytes.len() != 20 {
        return Err(AppError::BadRequest("Invalid key length".to_string()));
    }

    let token = payload.token.into_string();
    if !two_factor::verify_totp_code(&key, &token)? {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let two_factor_key_b64 = state.env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
    let secret_enc = two_factor::encrypt_secret_with_optional_key(two_factor_key_b64.as_deref(), &claims.sub, &key)?;
    two_factor::upsert_authenticator_secret(&db, &claims.sub, secret_enc, true, &now).await?;

    let _ = two_factor::get_or_create_recovery_code(&db, &claims.sub).await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorEnable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some("provider=authenticator".to_string()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(json!({
        "enabled": true,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

#[worker::send]
pub async fn activate_authenticator_put(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<EnableAuthenticatorData>,
) -> Result<Json<serde_json::Value>, AppError> {
    activate_authenticator(claims, State(state), headers, Json(payload)).await
}

#[worker::send]
pub async fn disable_authenticator_vw(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DisableAuthenticatorData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let stored_hash: Option<String> = db
        .prepare("SELECT master_password_hash FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(Some("master_password_hash"))
        .await
        .map_err(|_| AppError::Database)?;
    let Some(stored_hash) = stored_hash else {
        return Err(AppError::NotFound("User not found".to_string()));
    };
    if !constant_time_eq(stored_hash.as_bytes(), payload.master_password_hash.as_bytes()) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    if let Some(secret_enc) = two_factor::get_authenticator_secret_enc(&db, &claims.sub).await? {
        let two_factor_key_b64 = state.env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
        let secret_encoded =
            two_factor::decrypt_secret_with_optional_key(two_factor_key_b64.as_deref(), &claims.sub, &secret_enc)?;
        if secret_encoded.eq_ignore_ascii_case(payload.key.trim()) {
            two_factor::disable_authenticator(&db, &claims.sub).await?;
        } else {
            return Err(AppError::BadRequest(
                "TOTP key does not match recorded value".to_string(),
            ));
        }
    }

    let type_ = match payload.r#type {
        NumberOrString::Number(n) => n as i32,
        NumberOrString::String(s) => s.parse::<i32>().unwrap_or(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR),
    };

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorDisable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("type={type_}")),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(json!({
        "enabled": false,
        "keys": type_,
        "object": "twoFactorProvider"
    })))
}

#[worker::send]
pub async fn authenticator_enable(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<EnableAuthenticatorRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now().to_rfc3339();

    let secret_enc = two_factor::get_authenticator_secret_enc(&db, &claims.sub)
        .await?
        .ok_or_else(|| AppError::BadRequest("No pending authenticator setup".to_string()))?;
    let two_factor_key_b64 = state.env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
    let secret_encoded = match two_factor::decrypt_secret_with_optional_key(
        two_factor_key_b64.as_deref(),
        &claims.sub,
        &secret_enc,
    ) {
        Ok(v) => v,
        Err(e) => {
            let _ = two_factor::disable_authenticator(&db, &claims.sub).await;
            return Err(e);
        }
    };
    if !two_factor::verify_totp_code(&secret_encoded, &payload.code)? {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    }

    two_factor::upsert_authenticator_secret(&db, &claims.sub, secret_enc, true, &now).await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorEnable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some("provider=authenticator".to_string()),
            meta,
            ..Default::default()
        },
    );
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn authenticator_disable(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DisableAuthenticatorRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let secret_enc = two_factor::get_authenticator_secret_enc(&db, &claims.sub)
        .await?
        .ok_or_else(|| AppError::BadRequest("Authenticator not enabled".to_string()))?;
    let two_factor_key_b64 = state.env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
    let secret_encoded = two_factor::decrypt_secret_with_optional_key(
        two_factor_key_b64.as_deref(),
        &claims.sub,
        &secret_enc,
    )?;
    if !two_factor::verify_totp_code(&secret_encoded, &payload.code)? {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    }

    two_factor::disable_authenticator(&db, &claims.sub).await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorDisable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some("provider=authenticator".to_string()),
            meta,
            ..Default::default()
        },
    );
    Ok(Json(json!({})))
}

const EMAIL_TOKEN_SIZE: u8 = 6;
const EMAIL_EXPIRATION_TIME: i64 = 600;
const EMAIL_ATTEMPTS_LIMIT: u64 = 3;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendEmailData {
    pub email: String,
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailData {
    pub token: String,
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendEmailLoginData {
    #[serde(alias = "DeviceIdentifier")]
    pub device_identifier: Option<String>,
    #[serde(alias = "Email")]
    pub email: Option<String>,
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: Option<String>,
}

#[worker::send]
pub async fn get_email(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;

    log::debug!(
        target: targets::AUTH,
        "get_email_2fa_status called user_id={}",
        claims.sub
    );

    // 记录接收到的请求内容（脱敏）
    let has_password = payload.master_password_hash.is_some();
    let has_otp = payload.otp.is_some();
    log::debug!(
        target: targets::AUTH,
        "get_email_2fa_status request payload user_id={} has_password={} has_otp={}",
        claims.sub,
        has_password,
        has_otp
    );

    if let Err(e) = claims.verify_security_stamp(&db).await {
        log::warn!(
            target: targets::AUTH,
            "get_email_2fa_status security_stamp verification failed user_id={} error={:?}",
            claims.sub,
            e
        );
        return Err(e);
    }

    if let Err(e) = payload.validate(&db, &claims.sub).await {
        log::warn!(
            target: targets::AUTH,
            "get_email_2fa_status password validation failed user_id={} error={:?}",
            claims.sub,
            e
        );
        return Err(e);
    }

    log::info!(
        target: targets::AUTH,
        "get_email_2fa_status success user_id={}",
        claims.sub
    );

    let (enabled, mfa_email) = match two_factor::get_email_2fa(&db, &claims.sub).await? {
        Some((enabled, data)) => {
            let email_data = EmailTokenData::from_json(&data)?;
            (enabled, json!(email_data.email))
        }
        None => (false, serde_json::Value::Null),
    };

    Ok(Json(json!({
        "email": mfa_email,
        "enabled": enabled,
        "object": "twoFactorEmail"
    })))
}

#[worker::send]
pub async fn send_email(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SendEmailData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    PasswordOrOtpData {
        master_password_hash: payload.master_password_hash.clone(),
        otp: payload.otp,
    }
    .validate(&db, &claims.sub)
    .await?;

    if !notify::is_email_webhook_configured(&state.env) {
        log::warn!(
            target: targets::AUTH,
            "send_email_2fa failed: webhook not configured user_id={}",
            claims.sub
        );
        return Err(AppError::BadRequest("Email 2FA is not configured on server".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let generated_token = two_factor::generate_email_token(EMAIL_TOKEN_SIZE);
    let twofactor_data = EmailTokenData::new(payload.email.clone(), generated_token.clone());

    two_factor::upsert_email_2fa(
        &db,
        &claims.sub,
        two_factor::TWO_FACTOR_TYPE_EMAIL_VERIFICATION_CHALLENGE,
        false,
        &twofactor_data.to_json(),
        &now,
    )
    .await?;

    log::info!(
        target: targets::AUTH,
        "send_email_2fa_verification user_id={} email={}",
        claims.sub,
        payload.email
    );

    notify::send_email_token_background(
        &state.ctx,
        state.env.clone(),
        payload.email,
        generated_token,
        EmailType::TwoFactorEmail,
    );

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn verify_email(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<EmailData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    PasswordOrOtpData {
        master_password_hash: payload.master_password_hash,
        otp: payload.otp,
    }
    .validate(&db, &claims.sub)
    .await?;

    let data = two_factor::get_email_2fa_verification(&db, &claims.sub)
        .await?
        .ok_or_else(|| {
            log::warn!(
                target: targets::AUTH,
                "verify_email_2fa failed: no verification record user_id={}",
                claims.sub
            );
            AppError::BadRequest("Two factor not found".to_string())
        })?;

    let mut email_data = EmailTokenData::from_json(&data)?;

    let Some(issued_token) = &email_data.last_token else {
        log::warn!(
            target: targets::AUTH,
            "verify_email_2fa failed: no token available user_id={}",
            claims.sub
        );
        return Err(AppError::BadRequest("No token available".to_string()));
    };

    // 首先验证token是否匹配（常量时间比较）
    if !constant_time_eq(payload.token.as_bytes(), issued_token.as_bytes()) {
        // 验证失败，增加尝试次数
        email_data.add_attempt();
        log::warn!(
            target: targets::AUTH,
            "verify_email_2fa failed: invalid token user_id={} attempts={}",
            claims.sub,
            email_data.attempts
        );
        if email_data.attempts >= EMAIL_ATTEMPTS_LIMIT {
            email_data.reset_token();
        }
        let now = Utc::now().to_rfc3339();
        two_factor::upsert_email_2fa(
            &db,
            &claims.sub,
            two_factor::TWO_FACTOR_TYPE_EMAIL_VERIFICATION_CHALLENGE,
            false,
            &email_data.to_json(),
            &now,
        )
        .await?;
        return Err(AppError::BadRequest("Token is invalid".to_string()));
    }

    // token验证成功，先重置token并启用2FA
    email_data.reset_token();
    let now = Utc::now().to_rfc3339();
    two_factor::upsert_email_2fa(
        &db,
        &claims.sub,
        two_factor::TWO_FACTOR_PROVIDER_EMAIL,
        true,
        &email_data.to_json(),
        &now,
    )
    .await?;

    // 最后检查token是否过期（参考vaultwarden实现）
    if two_factor::is_token_expired(email_data.token_sent, EMAIL_EXPIRATION_TIME) {
        log::warn!(
            target: targets::AUTH,
            "verify_email_2fa failed: token expired user_id={}",
            claims.sub
        );
        return Err(AppError::BadRequest("Token has expired".to_string()));
    }

    log::info!(
        target: targets::AUTH,
        "verify_email_2fa success user_id={} email={}",
        claims.sub,
        email_data.email
    );

    let _ = two_factor::get_or_create_recovery_code(&db, &claims.sub).await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorEnable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some("provider=email".to_string()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(json!({
        "email": email_data.email,
        "enabled": true,
        "object": "twoFactorEmail"
    })))
}

#[worker::send]
pub async fn send_email_login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SendEmailLoginData>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !notify::is_email_webhook_configured(&state.env) {
        log::warn!(
            target: targets::AUTH,
            "send_email_login failed: webhook not configured"
        );
        return Err(AppError::BadRequest("Email 2FA is not configured on server".to_string()));
    }

    let db = db::get_db(&state.env)?;

    let user_id: Option<String> = if let Some(email) = &payload.email {
        if email.is_empty() {
            return Err(AppError::BadRequest("Email is required".to_string()));
        }

        let result: Option<serde_json::Value> = db
            .prepare("SELECT id, master_password_hash, password_salt FROM users WHERE email = ?1")
            .bind(&[email.into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;

        let Some(row) = result else {
            return Err(AppError::Unauthorized("Username or password is incorrect".to_string()));
        };

        let user_id = row.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let stored_hash = row.get("master_password_hash").and_then(|v| v.as_str()).unwrap_or("");
        let password_salt = row.get("password_salt").and_then(|v| v.as_str());

        if let Some(master_password_hash) = &payload.master_password_hash {
            let password_valid = if let Some(salt) = password_salt {
                crate::crypto::verify_password(master_password_hash, salt, stored_hash).await
            } else {
                constant_time_eq(stored_hash.as_bytes(), master_password_hash.as_bytes())
            };

            if !password_valid {
                return Err(AppError::Unauthorized("Username or password is incorrect".to_string()));
            }
        }

        Some(user_id)
    } else if let Some(device_identifier) = &payload.device_identifier {
        let result: Option<serde_json::Value> = db
            .prepare("SELECT user_id FROM devices WHERE device_identifier = ?1 ORDER BY updated_at DESC LIMIT 1")
            .bind(&[device_identifier.into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;

        result.and_then(|r| r.get("user_id").and_then(|v| v.as_str().map(|s| s.to_string())))
    } else {
        None
    };

    let Some(user_id) = user_id else {
        return Err(AppError::Unauthorized("Username or password is incorrect".to_string()));
    };

    let (enabled, data) = match two_factor::get_email_2fa(&db, &user_id).await? {
        Some((enabled, data)) => (enabled, data),
        None => {
            log::warn!(
                target: targets::AUTH,
                "send_email_login failed: email 2fa not found user_id={}",
                user_id
            );
            return Err(AppError::BadRequest("Two factor not found".to_string()));
        }
    };

    if !enabled {
        log::warn!(
            target: targets::AUTH,
            "send_email_login failed: email 2fa not enabled user_id={}",
            user_id
        );
        return Err(AppError::BadRequest("Email 2FA is not enabled".to_string()));
    }

    let mut email_data = EmailTokenData::from_json(&data)?;
    let generated_token = two_factor::generate_email_token(EMAIL_TOKEN_SIZE);
    email_data.set_token(generated_token.clone());

    let now = Utc::now().to_rfc3339();
    two_factor::upsert_email_2fa(
        &db,
        &user_id,
        two_factor::TWO_FACTOR_PROVIDER_EMAIL,
        true,
        &email_data.to_json(),
        &now,
    )
    .await?;

    log::info!(
        target: targets::AUTH,
        "send_email_login user_id={} email={}",
        user_id,
        email_data.email
    );

    notify::send_email_token_background(
        &state.ctx,
        state.env.clone(),
        email_data.email.clone(),
        generated_token,
        EmailType::TwoFactorLogin,
    );

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn disable_email(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    payload.validate(&db, &claims.sub).await?;

    two_factor::delete_email_2fa(&db, &claims.sub).await?;

    log::info!(
        target: targets::AUTH,
        "disable_email_2fa user_id={}",
        claims.sub
    );

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorDisable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some("provider=email".to_string()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(json!({
        "enabled": false,
        "type": two_factor::TWO_FACTOR_PROVIDER_EMAIL,
        "object": "twoFactorProvider"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableTwoFactorData {
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
    #[serde(rename = "type")]
    pub r#type: NumberOrString,
}

#[worker::send]
pub async fn disable_twofactor(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DisableTwoFactorData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    // 验证主密码
    PasswordOrOtpData {
        master_password_hash: payload.master_password_hash,
        otp: payload.otp,
    }
    .validate(&db, &claims.sub)
    .await?;

    // 解析类型
    let type_ = match payload.r#type {
        NumberOrString::Number(n) => n as i32,
        NumberOrString::String(s) => s.parse::<i32>().unwrap_or(two_factor::TWO_FACTOR_PROVIDER_EMAIL),
    };

    log::info!(
        target: targets::AUTH,
        "disable_twofactor user_id={} type={}",
        claims.sub,
        type_
    );

    // 根据类型删除对应的2FA
    match type_ {
        two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR => {
            two_factor::disable_authenticator(&db, &claims.sub).await?;
            log::info!(
                target: targets::AUTH,
                "disable_twofactor: authenticator disabled user_id={}",
                claims.sub
            );
        }
        two_factor::TWO_FACTOR_PROVIDER_EMAIL => {
            two_factor::delete_email_2fa(&db, &claims.sub).await?;
            log::info!(
                target: targets::AUTH,
                "disable_twofactor: email 2fa disabled user_id={}",
                claims.sub
            );
        }
        _ => {
            log::warn!(
                target: targets::AUTH,
                "disable_twofactor: unknown type user_id={} type={}",
                claims.sub,
                type_
            );
            return Err(AppError::BadRequest(format!("Unknown two factor type: {}", type_)));
        }
    }

    // 发送通知
    let provider_name = match type_ {
        two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR => "authenticator",
        two_factor::TWO_FACTOR_PROVIDER_EMAIL => "email",
        _ => "unknown",
    };

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorDisable,
        NotifyContext {
            user_id: Some(claims.sub.clone()),
            user_email: Some(claims.email),
            detail: Some(format!("provider={}", provider_name)),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(json!({
        "enabled": false,
        "type": type_,
        "object": "twoFactorProvider"
    })))
}

// PUT 方法别名，与 vaultwarden 保持一致
#[worker::send]
pub async fn disable_twofactor_put(
    claims: Claims,
    state: State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Json<DisableTwoFactorData>,
) -> Result<Json<serde_json::Value>, AppError> {
    disable_twofactor(claims, state, headers, payload).await
}

#[worker::send]
pub async fn get_recover(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    payload.validate(&db, &claims.sub).await?;

    log::debug!(
        target: targets::AUTH,
        "get_recover called user_id={}",
        claims.sub
    );

    let code = two_factor::get_or_create_recovery_code(&db, &claims.sub).await?;

    log::info!(
        target: targets::AUTH,
        "get_recover success user_id={}",
        claims.sub
    );

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorRecoveryCodeView,
        NotifyContext {
            user_id: Some(claims.sub.clone()),
            user_email: Some(claims.email.clone()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );

    Ok(Json(json!({
        "code": code,
        "object": "twoFactorRecover"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverTwoFactorData {
    pub master_password_hash: String,
    pub email: String,
    pub recovery_code: String,
}

#[worker::send]
pub async fn recover(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RecoverTwoFactorData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;

    log::info!(
        target: targets::AUTH,
        "recover called email={}",
        payload.email
    );

    let result: Option<serde_json::Value> = db
        .prepare("SELECT id, master_password_hash, password_salt FROM users WHERE email = ?1")
        .bind(&[payload.email.to_lowercase().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let Some(row) = result else {
        log::warn!(
            target: targets::AUTH,
            "recover failed: user not found email={}",
            payload.email
        );
        return Err(AppError::Unauthorized("Username or password is incorrect. Try again.".to_string()));
    };

    let user_id = row.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let stored_hash = row.get("master_password_hash").and_then(|v| v.as_str()).unwrap_or("");
    let password_salt = row.get("password_salt").and_then(|v| v.as_str());

    let password_valid = if let Some(salt) = password_salt {
        crate::crypto::verify_password(&payload.master_password_hash, salt, stored_hash).await
    } else {
        constant_time_eq::constant_time_eq(stored_hash.as_bytes(), payload.master_password_hash.as_bytes())
    };

    if !password_valid {
        log::warn!(
            target: targets::AUTH,
            "recover failed: password mismatch email={}",
            payload.email
        );
        return Err(AppError::Unauthorized("Username or password is incorrect. Try again.".to_string()));
    }

    let recovery_valid = two_factor::verify_recovery_code(&db, &user_id, &payload.recovery_code).await?;
    if !recovery_valid {
        log::warn!(
            target: targets::AUTH,
            "recover failed: invalid recovery code email={}",
            payload.email
        );
        return Err(AppError::BadRequest("Recovery code is incorrect. Try again.".to_string()));
    }

    two_factor::delete_all_two_factors(&db, &user_id).await?;
    two_factor::clear_recovery_code(&db, &user_id).await?;

    log::info!(
        target: targets::AUTH,
        "recover success: all 2fa removed user_id={} email={}",
        user_id,
        payload.email
    );

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorRecover,
        NotifyContext {
            user_id: Some(user_id),
            user_email: Some(payload.email),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(json!({})))
}
