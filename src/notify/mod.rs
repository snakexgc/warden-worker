pub mod types;
pub mod config;
pub mod context;
pub mod channels;
pub mod templates;
pub mod dispatcher;

pub use types::{CodeType, NotifyEvent, Notification, RequestMeta};
pub use context::{NotifyContext, extract_request_meta};
pub use dispatcher::{dispatch, dispatch_background, is_webhook_configured};

use crate::background::BackgroundExecutor;

#[derive(Debug, Clone, Copy)]
pub enum EmailType {
    TwoFactorEmail,
    TwoFactorLogin,
}

impl From<EmailType> for CodeType {
    fn from(value: EmailType) -> Self {
        match value {
            EmailType::TwoFactorEmail => CodeType::TwoFactorEmail,
            EmailType::TwoFactorLogin => CodeType::TwoFactorLogin,
        }
    }
}

pub async fn notify_best_effort(env: &worker::Env, event: NotifyEvent, ctx: NotifyContext) {
    if let Err(e) = dispatch(env, Notification::event(event, ctx)).await {
        log::warn!(target: crate::logging::targets::NOTIFY, "notify_best_effort failed: {:?}", e);
    }
}

pub fn notify_background(
    context: &BackgroundExecutor,
    env: worker::Env,
    event: NotifyEvent,
    ctx: NotifyContext,
) {
    dispatch_background(context, env, Notification::event(event, ctx));
}

pub fn send_password_hint_background(
    context: &BackgroundExecutor,
    env: worker::Env,
    ctx: NotifyContext,
) {
    dispatch_background(context, env, Notification::event(NotifyEvent::PasswordHint, ctx));
}

pub fn send_email_token_background(
    context: &BackgroundExecutor,
    env: worker::Env,
    email: String,
    token: String,
    email_type: EmailType,
) {
    dispatch_background(context, env, Notification::code(&email, &token, email_type.into()));
}

pub fn is_email_webhook_configured(env: &worker::Env) -> bool {
    is_webhook_configured(env)
}

pub async fn publish_auth_request(env: &worker::Env, user_id: &str, request_id: &str) -> Result<(), worker::Error> {
    let db = crate::db::get_db(env).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let user: Option<serde_json::Value> = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await?;

    let email = user.and_then(|u| u.get("email").and_then(|v| v.as_str()).map(|s| s.to_string()));

    let req: Option<serde_json::Value> = db
        .prepare("SELECT request_device_identifier, device_type, request_ip FROM auth_requests WHERE id = ?1")
        .bind(&[request_id.into()])?
        .first(None)
        .await?;

    let (device_id, device_type, ip) = if let Some(r) = req {
        (
            r.get("request_device_identifier").and_then(|v| v.as_str()).map(|s| s.to_string()),
            r.get("device_type").and_then(|v| v.as_i64()).map(|i| i as i32),
            r.get("request_ip").and_then(|v| v.as_str()).map(|s| s.to_string()),
        )
    } else {
        (None, None, None)
    };

    let mut meta = RequestMeta::default();
    meta.ip = ip;

    let ctx = NotifyContext {
        user_id: Some(user_id.to_string()),
        user_email: email,
        device_identifier: device_id,
        device_type,
        meta,
        ..Default::default()
    };

    notify_best_effort(env, NotifyEvent::AuthRequest, ctx).await;
    Ok(())
}

pub async fn publish_auth_response(env: &worker::Env, user_id: &str, request_id: &str) -> Result<(), worker::Error> {
    let db = crate::db::get_db(env).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let user: Option<serde_json::Value> = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await?;

    let email = user.and_then(|u| u.get("email").and_then(|v| v.as_str()).map(|s| s.to_string()));

    let req: Option<serde_json::Value> = db
        .prepare("SELECT response_device_identifier, approved FROM auth_requests WHERE id = ?1")
        .bind(&[request_id.into()])?
        .first(None)
        .await?;

    let (device_id, approved) = if let Some(r) = req {
        (
            r.get("response_device_identifier").and_then(|v| v.as_str()).map(|s| s.to_string()),
            r.get("approved").and_then(|v| v.as_i64()).map(|i| i == 1).unwrap_or(false),
        )
    } else {
        (None, false)
    };

    let detail = if approved {
        Some("已批准登录请求".to_string())
    } else {
        Some("已拒绝登录请求".to_string())
    };

    let ctx = NotifyContext {
        user_id: Some(user_id.to_string()),
        user_email: email,
        device_identifier: device_id,
        detail,
        ..Default::default()
    };

    notify_best_effort(env, NotifyEvent::AuthResponse, ctx).await;
    Ok(())
}
