use axum::http::HeaderMap;
use axum::{Json, extract::State};
use chrono::Utc;
use constant_time_eq::constant_time_eq;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::logging::targets;
use crate::notify::{self, EmailType, NotifyContext, NotifyEvent};
use crate::password;
use crate::router::AppState;
use crate::two_factor::{self, EmailTokenData};
use crate::two_factor_verification;
use crate::webauthn;

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
    /// New-style authorization issued by the get-* endpoints; when present it
    /// replaces the password/OTP check (upstream `acbf4901`).
    #[serde(default)]
    pub user_verification_token: Option<String>,
}

impl PasswordOrOtpData {
    async fn validate(&self, db: &worker::D1Database, user_id: &str) -> Result<(), AppError> {
        match (&self.master_password_hash, &self.otp) {
            (Some(master_password_hash), None) => {
                if !password::verify_user_password(db, user_id, master_password_hash).await? {
                    log::warn!(
                        target: targets::AUTH,
                        "PasswordOrOtpData.validate: password mismatch user_id={}",
                        user_id
                    );
                    return Err(AppError::Unauthorized("Invalid credentials".to_string()));
                }
                Ok(())
            }
            (None, Some(otp)) => {
                two_factor::validate_protected_action_otp(db, user_id, otp, true).await
            }
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
    #[serde(default)]
    user_verification_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableAuthenticatorData {
    key: String,
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(default)]
    user_verification_token: Option<String>,
    #[serde(rename = "type", default)]
    r#type: Option<NumberOrString>,
}

#[worker::send]
pub async fn two_factor_status(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let mut providers: Vec<serde_json::Value> = Vec::new();

    let authenticator_enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?;
    if authenticator_enabled {
        providers.push(json!({
            "enabled": true,
            "type": two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR,
            "object": "twoFactorProvider"
        }));
    }

    let email_enabled = two_factor::is_email_2fa_enabled(&db, &claims.sub).await?;
    if email_enabled && notify::is_email_webhook_configured(&state.env) {
        providers.push(json!({
            "enabled": true,
            "type": two_factor::TWO_FACTOR_PROVIDER_EMAIL,
            "object": "twoFactorProvider"
        }));
    }

    let webauthn_enabled = webauthn::is_webauthn_enabled(&db, &claims.sub).await?;
    if webauthn_enabled && webauthn::is_webauthn_2fa_supported(&headers) {
        providers.push(json!({
            "enabled": true,
            "type": webauthn::TWO_FACTOR_PROVIDER_WEBAUTHN,
            "object": "twoFactorProvider"
        }));
    }

    Ok(Json(json!({
        "data": providers,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn get_device_verification_settings(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    Ok(Json(json!({
        "isDeviceVerificationSectionEnabled": false,
        "unknownDeviceVerificationEnabled": false,
        "object": "deviceVerificationSettings"
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
    let secret_enc =
        two_factor::encrypt_secret_with_db_key(&db, &claims.sub, &secret_encoded).await?;

    two_factor::upsert_authenticator_secret(&db, &claims.sub, secret_enc, false, 0, &now).await?;

    let issuer = state
        .env
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

    let enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?;
    let key = if enabled {
        let secret_enc = two_factor::get_authenticator_secret_enc(&db, &claims.sub)
            .await?
            .ok_or_else(|| AppError::Internal)?;
        two_factor::decrypt_secret_with_key(&state.two_factor_key, &claims.sub, &secret_enc)?
    } else {
        two_factor::generate_totp_secret_base32_20()
    };

    if let Some(token) = payload.user_verification_token.as_deref() {
        two_factor_verification::validate_authenticator_token(
            &state.jwt_keys.access_secret,
            token,
            &claims.sub,
            &key,
            enabled,
        )?;
    } else {
        payload.validate(&db, &claims.sub).await?;
    }

    let user_verification_token = two_factor_verification::mint_authenticator_token(
        &state.jwt_keys.access_secret,
        &claims.sub,
        key.clone(),
        enabled,
    )?;

    // Keep the legacy flat fields for the old (v2026.7.0) web vault while the
    // new nested `authenticator` object serves upgraded clients.
    Ok(Json(json!({
        "enabled": enabled,
        "key": key,
        "object": "twoFactorAuthenticator",
        "authenticator": {
            "enabled": enabled,
            "key": key,
        },
        "userVerificationToken": user_verification_token,
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

    if let Some(token) = payload.user_verification_token.as_deref() {
        // Upstream `acbf4901`: the token was minted for the pre-enable state
        // and carries the key shown to the user.
        two_factor_verification::validate_authenticator_token(
            &state.jwt_keys.access_secret,
            token,
            &claims.sub,
            &payload.key,
            false,
        )?;
    } else {
        PasswordOrOtpData {
            master_password_hash: payload.master_password_hash.clone(),
            otp: payload.otp.clone(),
            user_verification_token: None,
        }
        .validate(&db, &claims.sub)
        .await?;
    }

    let key = payload.key.trim().to_uppercase();
    let key_bytes = Secret::Encoded(key.clone())
        .to_bytes()
        .map_err(|_| AppError::BadRequest("Invalid totp secret".to_string()))?;
    if key_bytes.len() != 20 {
        return Err(AppError::BadRequest("Invalid key length".to_string()));
    }

    let token = payload.token.into_string();
    let Some(last_used) = two_factor::match_current_totp_time_step(&key, &token)? else {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    };

    let now = Utc::now().to_rfc3339();
    let secret_enc = two_factor::encrypt_secret_with_key(&state.two_factor_key, &claims.sub, &key)?;
    two_factor::upsert_authenticator_secret(&db, &claims.sub, secret_enc, true, last_used, &now)
        .await?;

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

    // Keep the legacy flat fields for the old web vault alongside the new
    // nested `authenticator` object.
    Ok(Json(json!({
        "enabled": true,
        "key": key,
        "object": "twoFactorAuthenticator",
        "authenticator": {
            "enabled": true,
            "key": key,
        },
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

    if let Some(token) = payload.user_verification_token.as_deref() {
        // Token path (upstream `acbf4901`): the token was minted over the
        // stored key while the provider was enabled.
        let enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?;
        two_factor_verification::validate_authenticator_token(
            &state.jwt_keys.access_secret,
            token,
            &claims.sub,
            &payload.key,
            enabled,
        )?;
    } else {
        let master_password_hash = payload
            .master_password_hash
            .clone()
            .ok_or_else(|| AppError::BadRequest("No validation provided".to_string()))?;
        if !password::verify_user_password(&db, &claims.sub, &master_password_hash).await? {
            return Err(AppError::Unauthorized("Invalid credentials".to_string()));
        }
    }

    if let Some(secret_enc) = two_factor::get_authenticator_secret_enc(&db, &claims.sub).await? {
        let secret_encoded =
            two_factor::decrypt_secret_with_key(&state.two_factor_key, &claims.sub, &secret_enc)?;
        if secret_encoded.eq_ignore_ascii_case(payload.key.trim()) {
            two_factor::disable_authenticator(&db, &claims.sub).await?;
            two_factor::clear_remember_tokens(&db, &claims.sub).await?;
        } else {
            return Err(AppError::BadRequest(
                "TOTP key does not match recorded value".to_string(),
            ));
        }
    }

    let type_ = match payload.r#type {
        Some(NumberOrString::Number(n)) => n as i32,
        Some(NumberOrString::String(s)) => s
            .parse::<i32>()
            .unwrap_or(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR),
        None => two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR,
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
    let secret_encoded = match two_factor::decrypt_secret_with_key(
        &state.two_factor_key,
        &claims.sub,
        &secret_enc,
    ) {
        Ok(v) => v,
        Err(e) => {
            let _ = two_factor::disable_authenticator(&db, &claims.sub).await;
            return Err(e);
        }
    };
    let Some(last_used) = two_factor::match_current_totp_time_step(&secret_encoded, &payload.code)?
    else {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    };

    two_factor::upsert_authenticator_secret(&db, &claims.sub, secret_enc, true, last_used, &now)
        .await?;

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
    let secret_encoded =
        two_factor::decrypt_secret_with_key(&state.two_factor_key, &claims.sub, &secret_enc)?;
    if !two_factor::consume_totp_code(&db, &claims.sub, &secret_encoded, &payload.code).await? {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    }

    two_factor::disable_authenticator(&db, &claims.sub).await?;
    two_factor::clear_remember_tokens(&db, &claims.sub).await?;

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
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
    #[serde(default)]
    pub user_verification_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailData {
    pub token: String,
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
    #[serde(default)]
    pub user_verification_token: Option<String>,
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
    #[serde(alias = "AuthRequestId")]
    pub auth_request_id: Option<String>,
    #[serde(alias = "AuthRequestAccessCode")]
    pub auth_request_access_code: Option<String>,
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

    // Dual-path authorization (upstream `acbf4901`): a userVerificationToken
    // replaces the password/OTP check; the token itself is validated below
    // once the stored email is known.
    if payload.user_verification_token.is_none()
        && let Err(e) = payload.validate(&db, &claims.sub).await
    {
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
            (enabled, Some(email_data.email))
        }
        None => (false, None),
    };

    if let Some(token) = payload.user_verification_token.as_deref() {
        two_factor_verification::validate_email_token(
            &state.jwt_keys.access_secret,
            token,
            &claims.sub,
            mfa_email.as_deref(),
            enabled,
        )?;
    }

    let user_verification_token = two_factor_verification::mint_email_token(
        &state.jwt_keys.access_secret,
        &claims.sub,
        mfa_email.clone(),
        enabled,
    )?;

    // The legacy shape used a plain string under `email`; upstream `acbf4901`
    // turned it into an object, which is a hard key conflict. The new shape
    // wins (official clients expect it); the old web vault's Email 2FA card
    // may render oddly until the frontend is upgraded. Login flows are not
    // affected.
    Ok(Json(json!({
        "email": {
            "enabled": enabled,
            "email": mfa_email,
        },
        "enabled": enabled,
        "userVerificationToken": user_verification_token,
        "object": "twoFactorEmail",
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

    if let Some(token) = payload.user_verification_token.as_deref() {
        // Upstream `acbf4901` validates with enabled=false here, so the
        // address in the token is not compared while setting the provider up.
        two_factor_verification::validate_email_token(
            &state.jwt_keys.access_secret,
            token,
            &claims.sub,
            Some(payload.email.as_str()),
            false,
        )?;
    } else {
        PasswordOrOtpData {
            master_password_hash: payload.master_password_hash.clone(),
            otp: payload.otp.clone(),
            user_verification_token: None,
        }
        .validate(&db, &claims.sub)
        .await?;
    }

    if !notify::is_email_webhook_configured(&state.env) {
        log::warn!(
            target: targets::AUTH,
            "send_email_2fa failed: webhook not configured user_id={}",
            claims.sub
        );
        return Err(AppError::BadRequest(
            "Email 2FA is not configured on server".to_string(),
        ));
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
        payload.email.escape_debug()
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

    if let Some(token) = payload.user_verification_token.as_deref() {
        // Upstream validates with enabled=false during the setup flow, so the
        // token address is not compared here.
        two_factor_verification::validate_email_token(
            &state.jwt_keys.access_secret,
            token,
            &claims.sub,
            None,
            false,
        )?;
    } else {
        PasswordOrOtpData {
            master_password_hash: payload.master_password_hash,
            otp: payload.otp,
            user_verification_token: None,
        }
        .validate(&db, &claims.sub)
        .await?;
    }

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
        email_data.email.escape_debug()
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
    headers: HeaderMap,
    Json(payload): Json<SendEmailLoginData>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !notify::is_email_webhook_configured(&state.env) {
        log::warn!(
            target: targets::AUTH,
            "send_email_login failed: webhook not configured"
        );
        return Err(AppError::BadRequest(
            "Email 2FA is not configured on server".to_string(),
        ));
    }

    let db = db::get_db(&state.env)?;

    let rate_limit_identity = payload
        .email
        .as_deref()
        .map(crate::auth::normalize_email)
        .or_else(|| payload.device_identifier.clone())
        .unwrap_or_else(|| "unknown".to_string());
    super::identity::enforce_login_rate_limit_for(
        &state,
        &headers,
        "email2fa",
        &rate_limit_identity,
    )
    .await?;

    let user_id: Option<String> = if let Some(email) = &payload.email {
        let email = crate::auth::normalize_email(email);
        if email.is_empty() {
            return Err(AppError::BadRequest("Email is required".to_string()));
        }

        let result: Option<serde_json::Value> = db
            .prepare("SELECT id FROM users WHERE email = ?1")
            .bind(&[email.clone().into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;

        let Some(row) = result else {
            log::warn!(
                target: targets::AUTH,
                "email 2fa login failed: invalid credentials. IP: {}. Username: {}.",
                super::identity::client_ip_from_headers(&headers),
                email.escape_debug()
            );
            return Err(AppError::Unauthorized(
                "Username or password is incorrect".to_string(),
            ));
        };

        let user_id = row
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(master_password_hash) = payload
            .master_password_hash
            .as_deref()
            .filter(|hash| !hash.is_empty())
        {
            if !password::verify_user_password(&db, &user_id, master_password_hash).await? {
                log::warn!(
                    target: targets::AUTH,
                    "email 2fa login failed: invalid credentials. IP: {}. Username: {}.",
                    super::identity::client_ip_from_headers(&headers),
                    email.escape_debug()
                );
                return Err(AppError::Unauthorized(
                    "Username or password is incorrect".to_string(),
                ));
            }
        } else if let Some(auth_request_id) = payload
            .auth_request_id
            .as_deref()
            .filter(|id| !id.is_empty())
        {
            let access_code = payload
                .auth_request_access_code
                .as_deref()
                .filter(|code| !code.is_empty())
                .ok_or_else(|| AppError::Unauthorized("AuthRequest doesn't exist".to_string()))?;
            super::devices::ensure_auth_requests_table(&db).await?;
            super::devices::purge_expired_auth_requests(&db).await?;
            let auth_request: Value = db
                .prepare(
                    "SELECT device_type, request_ip, access_code_hash, authentication_date, approved, creation_date
                     FROM auth_requests WHERE id = ?1 AND user_id = ?2 LIMIT 1",
                )
                .bind(&[auth_request_id.into(), user_id.clone().into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Database)?
                .ok_or_else(|| AppError::Unauthorized("AuthRequest doesn't exist".to_string()))?;
            // Upstream `acb574b7`: an auth request is only usable for the
            // email 2FA login when it is approved, not consumed yet, younger
            // than five minutes, and still matches the requesting device, IP
            // and access code. Any deviation is reported uniformly.
            let approved = auth_request
                .get("approved")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                == 1;
            let already_authenticated = auth_request
                .get("authentication_date")
                .and_then(Value::as_str)
                .is_some();
            let request_expired = auth_request_login_expired(
                auth_request.get("creation_date").and_then(Value::as_str),
            );
            let expected_device_type = auth_request
                .get("device_type")
                .and_then(Value::as_i64)
                .unwrap_or(14) as i32;
            let actual_device_type = headers
                .get("device-type")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<i32>().ok())
                .unwrap_or(14);
            let expected_ip = auth_request
                .get("request_ip")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let expected_hash = auth_request
                .get("access_code_hash")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let actual_hash = format!("{:x}", Sha256::digest(access_code.as_bytes()));
            if !approved
                || already_authenticated
                || request_expired
                || actual_device_type != expected_device_type
                || super::identity::client_ip_from_headers(&headers) != expected_ip
                || !constant_time_eq(expected_hash.as_bytes(), actual_hash.as_bytes())
            {
                return Err(AppError::Unauthorized(
                    "AuthRequest doesn't exist".to_string(),
                ));
            }
        } else {
            return Err(AppError::BadRequest(
                "No password hash has been submitted.".to_string(),
            ));
        }

        Some(user_id)
    } else {
        let Some(device_identifier) = &payload.device_identifier else {
            return Err(AppError::BadRequest(
                "No device identifier has been submitted.".to_string(),
            ));
        };

        let result: Option<serde_json::Value> = db
            .prepare("SELECT user_id FROM devices WHERE device_identifier = ?1 ORDER BY updated_at DESC LIMIT 1")
            .bind(&[device_identifier.into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;

        result.and_then(|r| {
            r.get("user_id")
                .and_then(|v| v.as_str().map(|s| s.to_string()))
        })
    };

    let Some(user_id) = user_id else {
        log::warn!(
            target: targets::AUTH,
            "email 2fa login failed: invalid credentials. IP: {}. Device: {}.",
            super::identity::client_ip_from_headers(&headers),
            payload.device_identifier.as_deref().unwrap_or("unknown")
        );
        return Err(AppError::Unauthorized(
            "Username or password is incorrect".to_string(),
        ));
    };

    issue_email_login_token(&db, &state, &user_id).await?;

    Ok(Json(json!({})))
}

pub(crate) async fn issue_email_login_token(
    db: &worker::D1Database,
    state: &Arc<AppState>,
    user_id: &str,
) -> Result<(), AppError> {
    let (enabled, data) = match two_factor::get_email_2fa(db, user_id).await? {
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
        db,
        user_id,
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
        email_data.email.escape_debug()
    );

    notify::send_email_token_background(
        &state.ctx,
        state.env.clone(),
        email_data.email.clone(),
        generated_token,
        EmailType::TwoFactorLogin,
    );

    Ok(())
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

    if let Some(token) = payload.user_verification_token.as_deref() {
        // Upstream `acbf4901`: when disabling, the token must have been minted
        // for the currently stored address with the provider enabled. If
        // there is no email 2FA record there is nothing to disable and the
        // token check is skipped, matching upstream.
        if let Some((enabled, data)) = two_factor::get_email_2fa(&db, &claims.sub).await? {
            let email_data = EmailTokenData::from_json(&data)?;
            two_factor_verification::validate_email_token(
                &state.jwt_keys.access_secret,
                token,
                &claims.sub,
                Some(email_data.email.as_str()),
                enabled,
            )?;
        }
    } else {
        payload.validate(&db, &claims.sub).await?;
    }

    two_factor::delete_email_2fa(&db, &claims.sub).await?;
    two_factor::clear_remember_tokens(&db, &claims.sub).await?;

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
        user_verification_token: None,
    }
    .validate(&db, &claims.sub)
    .await?;

    // 解析类型
    let type_ = match payload.r#type {
        NumberOrString::Number(n) => n as i32,
        NumberOrString::String(s) => s
            .parse::<i32>()
            .unwrap_or(two_factor::TWO_FACTOR_PROVIDER_EMAIL),
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
        webauthn::TWO_FACTOR_PROVIDER_WEBAUTHN => {
            webauthn::disable_webauthn(&db, &claims.sub).await?;
            log::info!(
                target: targets::AUTH,
                "disable_twofactor: webauthn disabled user_id={}",
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
            return Err(AppError::BadRequest(format!(
                "Unknown two factor type: {}",
                type_
            )));
        }
    }

    two_factor::clear_remember_tokens(&db, &claims.sub).await?;

    // 发送通知
    let provider_name = match type_ {
        two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR => "authenticator",
        two_factor::TWO_FACTOR_PROVIDER_EMAIL => "email",
        webauthn::TWO_FACTOR_PROVIDER_WEBAUTHN => "webauthn",
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
        payload.email.escape_debug()
    );

    let result: Option<serde_json::Value> = db
        .prepare("SELECT id FROM users WHERE email = ?1")
        .bind(&[crate::auth::normalize_email(&payload.email).into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let Some(row) = result else {
        log::warn!(
            target: targets::AUTH,
            "recover failed: user not found email={}",
            payload.email.escape_debug()
        );
        return Err(AppError::Unauthorized(
            "Username or password is incorrect. Try again.".to_string(),
        ));
    };

    let user_id = row
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if !password::verify_user_password(&db, &user_id, &payload.master_password_hash).await? {
        log::warn!(
            target: targets::AUTH,
            "recover failed: password mismatch email={}",
            payload.email.escape_debug()
        );
        return Err(AppError::Unauthorized(
            "Username or password is incorrect. Try again.".to_string(),
        ));
    }

    let recovery_valid =
        two_factor::verify_recovery_code(&db, &user_id, &payload.recovery_code).await?;
    if !recovery_valid {
        log::warn!(
            target: targets::AUTH,
            "recover failed: invalid recovery code email={}",
            payload.email.escape_debug()
        );
        return Err(AppError::BadRequest(
            "Recovery code is incorrect. Try again.".to_string(),
        ));
    }

    two_factor::delete_all_two_factors(&db, &user_id).await?;
    two_factor::clear_remember_tokens(&db, &user_id).await?;
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

/// An auth request usable for the email 2FA login must be younger than five
/// minutes. A missing or unparsable creation date counts as expired
/// (upstream `acb574b7`).
fn auth_request_login_expired(creation_date: Option<&str>) -> bool {
    let Some(creation_date) = creation_date else {
        return true;
    };
    match chrono::DateTime::parse_from_rfc3339(creation_date) {
        Ok(created) => chrono::Utc::now() - chrono::Duration::minutes(5) >= created,
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::auth_request_login_expired;
    use chrono::{Duration, Utc};

    #[test]
    fn fresh_auth_request_is_not_expired() {
        let now = Utc::now().to_rfc3339();
        assert!(!auth_request_login_expired(Some(&now)));
    }

    #[test]
    fn auth_request_expires_after_five_minutes() {
        let stale = (Utc::now() - Duration::minutes(6)).to_rfc3339();
        assert!(auth_request_login_expired(Some(&stale)));
    }

    #[test]
    fn missing_or_invalid_creation_date_counts_as_expired() {
        assert!(auth_request_login_expired(None));
        assert!(auth_request_login_expired(Some("not-a-date")));
    }
}
