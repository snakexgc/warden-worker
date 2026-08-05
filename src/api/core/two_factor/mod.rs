pub mod authenticator;
pub mod duo;
pub mod duo_oidc;
pub mod email;
pub mod protected_actions;
pub mod webauthn;
pub mod yubikey;

use axum::{Json, extract::State, http::HeaderMap};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::{
    api::AppState,
    auth::Claims,
    crypto::password,
    db,
    db::models::two_factor,
    error::AppError,
    extensions::notify::{self, NotifyContext, NotifyEvent},
    worker_runtime::{logging::targets, webauthn as webauthn_runtime},
};

pub(crate) use email::issue_email_login_token;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOrOtpData {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

impl PasswordOrOtpData {
    pub(crate) async fn validate(
        &self,
        db: &worker::D1Database,
        user_id: &str,
    ) -> Result<(), AppError> {
        self.validate_with_delete(db, user_id, true).await
    }

    /// 对齐 Vaultwarden：`get_*` 类端点使用 `delete_if_valid=false`，不消耗受保护操作 OTP，
    /// 允许"先取 key、再以同一 OTP 激活"的上游流程。
    pub(crate) async fn validate_get(
        &self,
        db: &worker::D1Database,
        user_id: &str,
    ) -> Result<(), AppError> {
        self.validate_with_delete(db, user_id, false).await
    }

    async fn validate_with_delete(
        &self,
        db: &worker::D1Database,
        user_id: &str,
        delete_if_valid: bool,
    ) -> Result<(), AppError> {
        match (&self.master_password_hash, &self.otp) {
            (Some(master_password_hash), None) => {
                if !password::verify_user_password(db, user_id, master_password_hash).await? {
                    log::warn!(
                        target: targets::AUTH,
                        "PasswordOrOtpData.validate: password mismatch user_id={user_id}"
                    );
                    return Err(AppError::BadRequest("Invalid credentials".to_string()));
                }
                Ok(())
            }
            (None, Some(otp)) => {
                two_factor::validate_protected_action_otp(db, user_id, otp, delete_if_valid).await
            }
            _ => Err(AppError::BadRequest("No validation provided".to_string())),
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
    pub(crate) fn into_string(self) -> String {
        match self {
            Self::Number(value) => value.to_string(),
            Self::String(value) => value,
        }
    }
}

#[worker::send]
pub async fn two_factor_status(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let mut providers = Vec::new();

    if two_factor::is_authenticator_enabled(&db, &claims.sub).await? {
        providers.push(provider_json(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR));
    }
    if two_factor::is_email_2fa_enabled(&db, &claims.sub).await?
        && notify::is_email_webhook_configured(&state.env)
    {
        providers.push(provider_json(two_factor::TWO_FACTOR_PROVIDER_EMAIL));
    }
    if two_factor::is_external_two_factor_enabled(
        &db,
        &claims.sub,
        two_factor::TWO_FACTOR_PROVIDER_DUO,
    )
    .await?
    {
        providers.push(provider_json(two_factor::TWO_FACTOR_PROVIDER_DUO));
    }
    if two_factor::is_external_two_factor_enabled(
        &db,
        &claims.sub,
        two_factor::TWO_FACTOR_PROVIDER_YUBIKEY,
    )
    .await?
    {
        providers.push(provider_json(two_factor::TWO_FACTOR_PROVIDER_YUBIKEY));
    }
    if webauthn_runtime::is_webauthn_enabled(&db, &claims.sub).await?
        && webauthn_runtime::is_webauthn_2fa_supported(&headers)
    {
        providers.push(provider_json(
            webauthn_runtime::TWO_FACTOR_PROVIDER_WEBAUTHN,
        ));
    }

    Ok(Json(json!({
        "data": providers,
        "object": "list",
        "continuationToken": null
    })))
}

fn provider_json(provider_type: i32) -> Value {
    json!({
        "enabled": true,
        "type": provider_type,
        "object": "twoFactorProvider"
    })
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableTwoFactorData {
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
    #[serde(rename = "type")]
    pub provider_type: NumberOrString,
}

#[worker::send]
pub async fn disable_twofactor(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    PasswordOrOtpData {
        master_password_hash: payload.master_password_hash,
        otp: payload.otp,
    }
    .validate(&db, &claims.sub)
    .await?;
    let provider_type = match payload.provider_type {
        NumberOrString::Number(value) => value as i32,
        NumberOrString::String(value) => value
            .parse::<i32>()
            .unwrap_or(two_factor::TWO_FACTOR_PROVIDER_EMAIL),
    };

    match provider_type {
        two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR => {
            two_factor::disable_authenticator(&db, &claims.sub).await?
        }
        two_factor::TWO_FACTOR_PROVIDER_EMAIL => {
            two_factor::delete_email_2fa(&db, &claims.sub).await?
        }
        two_factor::TWO_FACTOR_PROVIDER_DUO | two_factor::TWO_FACTOR_PROVIDER_YUBIKEY => {
            two_factor::delete_external_two_factor(&db, &claims.sub, Some(provider_type)).await?
        }
        webauthn_runtime::TWO_FACTOR_PROVIDER_WEBAUTHN => {
            webauthn_runtime::disable_webauthn(&db, &claims.sub).await?
        }
        _ => {
            return Err(AppError::BadRequest(format!(
                "Unknown two factor type: {provider_type}"
            )));
        }
    }

    // 对齐 Vaultwarden enforce_2fa_policy：移除最后一个 2FA 后，
    // 撤销用户在启用了 Two-Factor Authentication（策略 type=0）组织中的非 Owner/Admin 成员身份
    let remaining = two_factor::is_authenticator_enabled(&db, &claims.sub).await?
        || two_factor::is_email_2fa_enabled(&db, &claims.sub).await?
        || two_factor::is_external_two_factor_enabled(
            &db,
            &claims.sub,
            two_factor::TWO_FACTOR_PROVIDER_DUO,
        )
        .await?
        || two_factor::is_external_two_factor_enabled(
            &db,
            &claims.sub,
            two_factor::TWO_FACTOR_PROVIDER_YUBIKEY,
        )
        .await?
        || webauthn_runtime::is_webauthn_enabled(&db, &claims.sub).await?;
    if !remaining {
        enforce_2fa_policy(&db, &state.env, &claims.sub).await?;
    }
    let provider_name = match provider_type {
        two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR => "authenticator",
        two_factor::TWO_FACTOR_PROVIDER_EMAIL => "email",
        two_factor::TWO_FACTOR_PROVIDER_DUO => "duo",
        two_factor::TWO_FACTOR_PROVIDER_YUBIKEY => "yubikey",
        webauthn_runtime::TWO_FACTOR_PROVIDER_WEBAUTHN => "webauthn",
        _ => "unknown",
    };
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorDisable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("provider={provider_name}")),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );
    Ok(Json(json!({
        "enabled": false,
        "type": provider_type,
        "object": "twoFactorProvider"
    })))
}

pub async fn disable_twofactor_put(
    claims: Claims,
    state: State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    disable_twofactor(claims, state, headers, payload).await
}

#[worker::send]
pub async fn get_recover(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    payload.validate_get(&db, &claims.sub).await?;
    let code = two_factor::get_or_create_recovery_code(&db, &claims.sub).await?;
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorRecoveryCodeView,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
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
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    let normalized_email = crate::auth::normalize_email(&payload.email);
    let user_id = db
        .prepare("SELECT id FROM users WHERE email = ?1")
        .bind(&[normalized_email.into()])?
        .first::<String>(Some("id"))
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| {
            AppError::BadRequest("Username or password is incorrect. Try again.".to_string())
        })?;
    if !password::verify_user_password(&db, &user_id, &payload.master_password_hash).await? {
        return Err(AppError::BadRequest(
            "Username or password is incorrect. Try again.".to_string(),
        ));
    }
    if !two_factor::verify_recovery_code(&db, &user_id, &payload.recovery_code).await? {
        return Err(AppError::BadRequest(
            "Recovery code is incorrect. Try again.".to_string(),
        ));
    }
    two_factor::delete_all_two_factors(&db, &user_id).await?;
    two_factor::clear_recovery_code(&db, &user_id).await?;
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorRecover,
        NotifyContext {
            user_id: Some(user_id),
            user_email: Some(payload.email),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );
    Ok(Json(json!({})))
}

pub async fn process_incomplete_notifications(env: &worker::Env) -> Result<usize, AppError> {
    use crate::db::models::two_factor_incomplete::TwoFactorIncomplete;

    let time_limit = TwoFactorIncomplete::time_limit_minutes(env);
    if time_limit <= 0 || !notify::is_webhook_configured(env) {
        return Ok(0);
    }
    let db = db::get_db(env)?;
    let threshold = (Utc::now() - Duration::minutes(time_limit))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let logins = TwoFactorIncomplete::find_logins_before(&db, &threshold).await?;
    let mut delivered = 0;
    for login in logins {
        let email = db
            .prepare("SELECT email FROM users WHERE id = ?1")
            .bind(&[login.user_id.clone().into()])?
            .first::<String>(Some("email"))
            .await
            .map_err(|_| AppError::Database)?;
        let Some(email) = email else {
            login.delete(&db).await?;
            continue;
        };
        let notification = notify::Notification::event(
            NotifyEvent::LoginFailed,
            NotifyContext {
                user_id: Some(login.user_id.clone()),
                user_email: Some(email),
                device_identifier: Some(login.device_id.clone()),
                device_name: Some(login.device_name.clone()),
                device_type: Some(login.device_type),
                detail: Some(format!(
                    "Two-factor login started at {} was not completed within {time_limit} minutes",
                    login.login_time
                )),
                meta: notify::RequestMeta {
                    ip: Some(login.ip_address.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        if notify::dispatch(env, notification).await.is_ok() {
            login.delete(&db).await?;
            delivered += 1;
        }
    }
    Ok(delivered)
}

/// 对齐 Vaultwarden `enforce_2fa_policy`：
/// 用户移除最后一个 2FA 后，撤销其在启用了 "Two-Factor Authentication"（策略 type=0）
/// 组织中的非 Owner/Admin 成员身份，并记录组织成员撤销事件。
const TWO_FACTOR_POLICY_REVOKE_OFFSET: i32 = 128;
const TWO_FACTOR_POLICY_MEMBER_USER: i32 = 2;
const TWO_FACTOR_POLICY_MEMBER_MANAGER: i32 = 3;

async fn enforce_2fa_policy(
    db: &worker::D1Database,
    env: &worker::Env,
    user_id: &str,
) -> Result<(), AppError> {
    let rows: Vec<Value> = db
        .prepare(
            "SELECT m.id AS membership_id, m.organization_id, m.member_type
             FROM users_organizations m
             JOIN org_policies p ON p.organization_id = m.organization_id
             WHERE m.user_id = ?1 AND m.status = 2 AND p.type = 0 AND p.enabled = 1",
        )
        .bind(&[user_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    for row in rows {
        let Some(member_type) = row
            .get("member_type")
            .and_then(Value::as_i64)
            .map(|value| value as i32)
        else {
            continue;
        };
        // 策略只适用于非 Owner/Admin 成员
        if member_type != TWO_FACTOR_POLICY_MEMBER_USER
            && member_type != TWO_FACTOR_POLICY_MEMBER_MANAGER
        {
            continue;
        }
        let Some(membership_id) = row.get("membership_id").and_then(Value::as_str) else {
            continue;
        };
        let Some(org_id) = row.get("organization_id").and_then(Value::as_str) else {
            continue;
        };
        db.prepare(
            "UPDATE users_organizations SET status = status - ?1, updated_at = ?2 WHERE id = ?3",
        )
        .bind(&[
            TWO_FACTOR_POLICY_REVOKE_OFFSET.into(),
            db::now_rfc3339_millis().into(),
            membership_id.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        super::events::log_event(db, env, 1511, Some(user_id), Some(org_id), None, user_id).await?;
    }
    Ok(())
}
