use axum::{Json, extract::State, http::HeaderMap};
use chrono::Utc;
use constant_time_eq::constant_time_eq;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::{
    api::AppState,
    auth::Claims,
    crypto::password,
    db,
    db::models::{
        auth_request,
        two_factor::{self, EmailTokenData},
    },
    error::AppError,
    extensions::notify::{self, EmailType, NotifyContext, NotifyEvent},
    worker_runtime::logging::targets,
};

use super::PasswordOrOtpData;

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
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    payload.validate_get(&db, &claims.sub).await?;

    let (enabled, email) = match two_factor::get_email_2fa(&db, &claims.sub).await? {
        Some((enabled, data)) => {
            let email_data = EmailTokenData::from_json(&data)?;
            (enabled, json!(email_data.email))
        }
        None => (false, Value::Null),
    };
    Ok(Json(json!({
        "email": email,
        "enabled": enabled,
        "object": "twoFactorEmail"
    })))
}

#[worker::send]
pub async fn send_email(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SendEmailData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    PasswordOrOtpData {
        master_password_hash: payload.master_password_hash.clone(),
        otp: payload.otp,
    }
    .validate(&db, &claims.sub)
    .await?;
    if !notify::is_email_webhook_configured(&state.env) {
        return Err(AppError::BadRequest(
            "Email 2FA is not configured on server".to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    let token = two_factor::generate_email_token(EMAIL_TOKEN_SIZE);
    let data = EmailTokenData::new(payload.email.clone(), token.clone());
    two_factor::upsert_email_2fa(
        &db,
        &claims.sub,
        two_factor::TWO_FACTOR_TYPE_EMAIL_VERIFICATION_CHALLENGE,
        false,
        &data.to_json(),
        &now,
    )
    .await?;
    notify::send_email_token_background(
        &state.ctx,
        state.env.clone(),
        payload.email,
        token,
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
) -> Result<Json<Value>, AppError> {
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
        .ok_or_else(|| AppError::BadRequest("Two factor not found".to_string()))?;
    let mut email_data = EmailTokenData::from_json(&data)?;
    let issued_token = email_data
        .last_token
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("No token available".to_string()))?;
    if !constant_time_eq(payload.token.as_bytes(), issued_token.as_bytes()) {
        email_data.add_attempt();
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
    if two_factor::is_token_expired(email_data.token_sent, EMAIL_EXPIRATION_TIME) {
        return Err(AppError::BadRequest("Token has expired".to_string()));
    }

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
    let _ = two_factor::get_or_create_recovery_code(&db, &claims.sub).await?;
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorEnable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some("provider=email".to_string()),
            meta: notify::extract_request_meta(&headers),
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
) -> Result<Json<Value>, AppError> {
    if !notify::is_email_webhook_configured(&state.env) {
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
    crate::api::identity::enforce_login_rate_limit_for(
        &state,
        &headers,
        "email2fa",
        &rate_limit_identity,
    )
    .await?;

    let user_id = if let Some(email) = payload.email.as_deref() {
        authenticate_email_request(&db, &headers, &payload, email).await?
    } else {
        let device_identifier = payload.device_identifier.as_deref().ok_or_else(|| {
            AppError::BadRequest("No device identifier has been submitted.".to_string())
        })?;
        db.prepare(
            "SELECT user_id FROM devices WHERE device_identifier = ?1
             ORDER BY updated_at DESC LIMIT 1",
        )
        .bind(&[device_identifier.into()])?
        .first::<String>(Some("user_id"))
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::BadRequest("Username or password is incorrect".to_string()))?
    };
    issue_email_login_token(&db, &state, &user_id).await?;
    Ok(Json(json!({})))
}

async fn authenticate_email_request(
    db: &worker::D1Database,
    headers: &HeaderMap,
    payload: &SendEmailLoginData,
    raw_email: &str,
) -> Result<String, AppError> {
    let email = crate::auth::normalize_email(raw_email);
    if email.is_empty() {
        return Err(AppError::BadRequest("Email is required".to_string()));
    }
    let user_id = db
        .prepare("SELECT id FROM users WHERE email = ?1")
        .bind(&[email.into()])?
        .first::<String>(Some("id"))
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::BadRequest("Username or password is incorrect".to_string()))?;

    if let Some(master_password_hash) = payload
        .master_password_hash
        .as_deref()
        .filter(|hash| !hash.is_empty())
    {
        if !password::verify_user_password(db, &user_id, master_password_hash).await? {
            return Err(AppError::BadRequest(
                "Username or password is incorrect".to_string(),
            ));
        }
        return Ok(user_id);
    }

    let auth_request_id = payload
        .auth_request_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| AppError::BadRequest("No password hash has been submitted.".to_string()))?;
    let access_code = payload
        .auth_request_access_code
        .as_deref()
        .filter(|code| !code.is_empty())
        .ok_or_else(|| AppError::BadRequest("AuthRequest doesn't exist".to_string()))?;
    auth_request::purge_expired(db).await?;
    let request: Value = db
        .prepare(
            "SELECT device_type, request_ip, access_code_hash, authentication_date
             FROM auth_requests WHERE id = ?1 AND user_id = ?2 LIMIT 1",
        )
        .bind(&[auth_request_id.into(), user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::BadRequest("AuthRequest doesn't exist".to_string()))?;
    if request
        .get("authentication_date")
        .and_then(Value::as_str)
        .is_some()
    {
        return Err(AppError::BadRequest(
            "AuthRequest doesn't exist".to_string(),
        ));
    }
    let expected_device_type = request
        .get("device_type")
        .and_then(Value::as_i64)
        .unwrap_or(14) as i32;
    let actual_device_type = headers
        .get("device-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<i32>().ok())
        .unwrap_or(14);
    let expected_ip = request
        .get("request_ip")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expected_hash = request
        .get("access_code_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let actual_hash = format!("{:x}", Sha256::digest(access_code.as_bytes()));
    if actual_device_type != expected_device_type
        || crate::api::identity::client_ip_from_headers(headers) != expected_ip
        || !constant_time_eq(expected_hash.as_bytes(), actual_hash.as_bytes())
    {
        return Err(AppError::BadRequest(
            "AuthRequest doesn't exist".to_string(),
        ));
    }
    Ok(user_id)
}

pub(crate) async fn issue_email_login_token(
    db: &worker::D1Database,
    state: &Arc<AppState>,
    user_id: &str,
) -> Result<(), AppError> {
    let (enabled, data) = two_factor::get_email_2fa(db, user_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Two factor not found".to_string()))?;
    if !enabled {
        return Err(AppError::BadRequest("Email 2FA is not enabled".to_string()));
    }
    let mut email_data = EmailTokenData::from_json(&data)?;
    let token = two_factor::generate_email_token(EMAIL_TOKEN_SIZE);
    email_data.set_token(token.clone());
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
    notify::send_email_token_background(
        &state.ctx,
        state.env.clone(),
        email_data.email,
        token,
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
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    payload.validate(&db, &claims.sub).await?;
    two_factor::delete_email_2fa(&db, &claims.sub).await?;
    log::info!(
        target: targets::AUTH,
        "disable_email_2fa user_id={}",
        claims.sub
    );
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorDisable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some("provider=email".to_string()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );
    Ok(Json(json!({
        "enabled": false,
        "type": two_factor::TWO_FACTOR_PROVIDER_EMAIL,
        "object": "twoFactorProvider"
    })))
}
