use axum::{Json, extract::State, http::HeaderMap};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::{
    api::AppState,
    auth::Claims,
    crypto::password,
    db,
    db::models::two_factor,
    error::AppError,
    extensions::notify::{self, NotifyContext, NotifyEvent},
};

use super::{NumberOrString, PasswordOrOtpData};

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
    provider_type: NumberOrString,
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
        .map(|value| value.to_string())
        .unwrap_or_else(|| "Warden Worker".to_string())
        .replace(':', "");
    let account = user_email.replace(':', "");
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret_encoded.clone())
            .to_bytes()
            .map_err(|_| AppError::Internal)?,
        Some(issuer),
        account,
    )
    .map_err(|_| AppError::Internal)?;

    Ok(Json(json!({
        "secret": secret_encoded,
        "otpauth": totp.get_url(),
        "qrBase64": totp.get_qr_base64().map_err(|_| AppError::Internal)?
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
        two_factor::decrypt_secret_with_key(&state.two_factor_key, &claims.sub, &secret_enc)?
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
    let Some(last_used) = two_factor::match_current_totp_time_step(&key, &token)? else {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    };

    let now = Utc::now().to_rfc3339();
    let secret_enc = two_factor::encrypt_secret_with_key(&state.two_factor_key, &claims.sub, &key)?;
    two_factor::upsert_authenticator_secret(&db, &claims.sub, secret_enc, true, last_used, &now)
        .await?;
    let _ = two_factor::get_or_create_recovery_code(&db, &claims.sub).await?;

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorEnable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some("provider=authenticator".to_string()),
            meta: notify::extract_request_meta(&headers),
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
pub async fn disable_authenticator(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DisableAuthenticatorData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    if !password::verify_user_password(&db, &claims.sub, &payload.master_password_hash).await? {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    if let Some(secret_enc) = two_factor::get_authenticator_secret_enc(&db, &claims.sub).await? {
        let secret =
            two_factor::decrypt_secret_with_key(&state.two_factor_key, &claims.sub, &secret_enc)?;
        if !secret.eq_ignore_ascii_case(payload.key.trim()) {
            return Err(AppError::BadRequest(
                "TOTP key does not match recorded value".to_string(),
            ));
        }
        two_factor::disable_authenticator(&db, &claims.sub).await?;
    }

    let provider_type = match payload.provider_type {
        NumberOrString::Number(value) => value as i32,
        NumberOrString::String(value) => value
            .parse::<i32>()
            .unwrap_or(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR),
    };
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorDisable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("type={provider_type}")),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );
    Ok(Json(json!({
        "enabled": false,
        "keys": provider_type,
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
    let secret = match two_factor::decrypt_secret_with_key(
        &state.two_factor_key,
        &claims.sub,
        &secret_enc,
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = two_factor::disable_authenticator(&db, &claims.sub).await;
            return Err(error);
        }
    };
    let Some(last_used) = two_factor::match_current_totp_time_step(&secret, &payload.code)? else {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    };
    two_factor::upsert_authenticator_secret(&db, &claims.sub, secret_enc, true, last_used, &now)
        .await?;
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorEnable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some("provider=authenticator".to_string()),
            meta: notify::extract_request_meta(&headers),
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
    let secret =
        two_factor::decrypt_secret_with_key(&state.two_factor_key, &claims.sub, &secret_enc)?;
    if !two_factor::consume_totp_code(&db, &claims.sub, &secret, &payload.code).await? {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    }
    two_factor::disable_authenticator(&db, &claims.sub).await?;
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorDisable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some("provider=authenticator".to_string()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );
    Ok(Json(json!({})))
}
