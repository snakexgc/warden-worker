use axum::{Json, extract::State};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::{
    api::AppState, auth::Claims, db, db::models::two_factor, error::AppError, extensions::notify,
};

const OTP_SIZE: u8 = 6;
const REQUEST_COOLDOWN_SECONDS: i64 = 30;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectedActionVerify {
    #[serde(rename = "OTP", alias = "otp")]
    otp: String,
}

#[worker::send]
pub async fn request_otp(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    if !notify::is_email_webhook_configured(&state.env) {
        return Err(AppError::BadRequest(
            "Email verification is not configured on server".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    if let Some(existing) = two_factor::get_protected_action_otp(&db, &claims.sub).await? {
        let elapsed = Utc::now().timestamp().saturating_sub(existing.token_sent);
        if elapsed < REQUEST_COOLDOWN_SECONDS {
            return Err(AppError::BadRequest(format!(
                "Please wait {} seconds before requesting another code.",
                REQUEST_COOLDOWN_SECONDS - elapsed
            )));
        }
    }
    let email = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first::<String>(Some("email"))
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let token = two_factor::generate_email_token(OTP_SIZE);
    let data = two_factor::ProtectedActionOtpData::new(token.clone());
    let now = Utc::now().to_rfc3339();
    two_factor::upsert_protected_action_otp(&db, &claims.sub, &data, &now).await?;
    notify::send_email_token_background(
        &state.ctx,
        state.env.clone(),
        email,
        token,
        notify::EmailType::TwoFactorLogin,
    );
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn verify_otp(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ProtectedActionVerify>,
) -> Result<Json<Value>, AppError> {
    if !notify::is_email_webhook_configured(&state.env) {
        return Err(AppError::BadRequest(
            "Email verification is not configured on server".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    two_factor::validate_protected_action_otp(&db, &claims.sub, &payload.otp, true).await?;
    Ok(Json(json!({})))
}
