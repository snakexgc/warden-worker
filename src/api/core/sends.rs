use axum::{
    Json,
    extract::{Multipart, Path, Query, State},
    http::HeaderMap,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use constant_time_eq::constant_time_eq;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use std::sync::Arc;
use uuid::Uuid;
use worker::query;

use crate::{
    api::AppState,
    api::notifications::{self, UpdateType},
    auth::Claims,
    db,
    db::models::send::{
        SEND_TYPE_FILE, SEND_TYPE_TEXT, SendAccessData, SendDBModel, SendData, SendFileDBModel,
        send_to_json, send_to_json_access, uuid_from_access_id,
    },
    error::AppError,
    extensions::notify::{self, NotifyContext, NotifyEvent},
    worker_runtime::logging::targets,
    worker_runtime::r2_file,
};

const SEND_FILES_BUCKET_BINDING: &str = "SEND_FILES_BUCKET";
const SEND_ACCESS_RATE_LIMITER_BINDING: &str = "SEND_ACCESS_LIMITER";
const SEND_ACCESS_TOKEN_ISSUER: &str = "warden-worker|send";
const SEND_ACCESS_TOKEN_TTL_MINUTES: i64 = 2;
const SEND_PASSWORD_ITERATIONS: i32 = 100_000;

/// Cookie name for Turnstile send-access pass (HttpOnly, signed JWT for backend)
const SEND_ACCESS_COOKIE: &str = "cf_send_pass";
/// Cookie name for frontend JS detection (non-HttpOnly, simple flag)
const SEND_ACCESS_FLAG_COOKIE: &str = "cf_send_pass_ok";
/// Cookie / token validity in minutes
const SEND_ACCESS_COOKIE_TTL_MINUTES: i64 = 5;
/// Cloudflare Turnstile siteverify endpoint
const TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// D1 free tier: 500 MB
const D1_MAX_BYTES: i64 = 500 * 1024 * 1024;
/// R2 free tier: 10 GB
const R2_MAX_BYTES: i64 = 10 * 1024 * 1024 * 1024;
/// Reject uploads when remaining space < 20% of free tier
const STORAGE_MIN_FREE_RATIO: f64 = 0.20;

fn now_rfc3339_millis() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>, AppError> {
    let dt = DateTime::parse_from_rfc3339(s)
        .map_err(|_| AppError::BadRequest("Invalid date".to_string()))?;
    Ok(dt.with_timezone(&Utc))
}

fn request_client_ip(headers: &HeaderMap) -> Option<String> {
    let ip = crate::auth::client_ip_from_headers(headers);
    (ip != "0.0.0.0").then_some(ip)
}

/// Check whether Turnstile is configured. Returns `true` when both the site key
/// (public) and secret key are present.
fn turnstile_enabled(state: &Arc<AppState>) -> bool {
    let has_site = state
        .env
        .var("TURNSTILE_SITE_KEY")
        .ok()
        .map(|v| !v.to_string().is_empty())
        .unwrap_or(false);
    let has_secret = state
        .env
        .secret("TURNSTILE_SECRET_KEY")
        .ok()
        .map(|v| !v.to_string().is_empty())
        .unwrap_or(false);
    has_site && has_secret
}

/// Call Cloudflare Turnstile siteverify API to validate a challenge token.
async fn verify_turnstile_token(
    state: &Arc<AppState>,
    token: &str,
    client_ip: Option<&str>,
) -> Result<(), AppError> {
    let secret = state
        .env
        .secret("TURNSTILE_SECRET_KEY")
        .map_err(|_| AppError::Internal)?
        .to_string();

    let mut body = json!({
        "secret": secret,
        "response": token
    });
    if let Some(ip) = client_ip {
        body.as_object_mut()
            .unwrap()
            .insert("remoteip".to_string(), Value::String(ip.to_string()));
    }

    let headers = worker::Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(|_| AppError::Internal)?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(
            &serde_json::to_string(&body).map_err(|_| AppError::Internal)?,
        )));
    let request = worker::Request::new_with_init(TURNSTILE_VERIFY_URL, &init)
        .map_err(|_| AppError::Internal)?;
    let mut response = worker::Fetch::Request(request)
        .send()
        .await
        .map_err(|_| AppError::Internal)?;
    let result: Value = response.json().await.map_err(|_| AppError::Internal)?;

    if result.get("success").and_then(|v| v.as_bool()) == Some(true) {
        log::info!(target: targets::AUTH, "turnstile.verify.success");
        Ok(())
    } else {
        let codes = result.get("error-codes").cloned().unwrap_or(json!([]));
        log::warn!(target: targets::AUTH, "turnstile.verify.fail codes={}", codes);
        Err(AppError::Unauthorized(
            "Turnstile verification failed".to_string(),
        ))
    }
}

// ─── Signed cookie helpers for Turnstile send-access pass ───

#[derive(Debug, Serialize, Deserialize)]
struct SendAccessPassClaims {
    /// "send_access" – fixed audience
    aud: String,
    exp: usize,
    iat: usize,
}

fn validate_deletion_date(deletion_date: &str) -> Result<(), AppError> {
    let deletion_date = parse_rfc3339(deletion_date)?;
    if deletion_date > Utc::now() + chrono::Duration::days(31) {
        return Err(AppError::BadRequest(
            "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again."
                .to_string(),
        ));
    }
    Ok(())
}

async fn enforce_organization_send_policies(
    db: &worker::D1Database,
    user_id: &str,
    hide_email: Option<bool>,
) -> Result<(), AppError> {
    if super::organizations::policy_applies_to_user(db, user_id, 6).await? {
        return Err(AppError::Forbidden(
            "Due to an organization policy, you may only delete an existing Send".to_string(),
        ));
    }
    if hide_email.unwrap_or(false)
        && super::organizations::hide_send_email_is_disabled(db, user_id).await?
    {
        return Err(AppError::Forbidden(
            "Due to an organization policy, you cannot hide your email on a Send".to_string(),
        ));
    }
    Ok(())
}

pub(crate) async fn rotate_send_data(
    db: &worker::D1Database,
    user_id: &str,
    payload: SendData,
    now: &str,
) -> Result<(), AppError> {
    enforce_organization_send_policies(db, user_id, payload.hide_email).await?;
    let send_id = payload._id.clone().ok_or_else(|| {
        AppError::BadRequest("Send id is required during key rotation".to_string())
    })?;
    let existing = get_send_by_id_and_user(db, &send_id, user_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Send doesn't exist".to_string()))?;
    if existing.r#type != payload.r#type {
        return Err(AppError::BadRequest("Cannot change send type".to_string()));
    }
    reject_unsupported_email_verification(&payload)?;
    validate_deletion_date(&payload.deletion_date)?;

    let name = payload.name.clone();
    let notes = payload.notes.clone();
    let password = payload.password.clone();
    let max_access_count = payload.max_access_count;
    let expiration_date = payload.expiration_date.clone();
    let deletion_date = payload.deletion_date.clone();
    let disabled = payload.disabled;
    let hide_email = payload.hide_email;
    let (send_type, key, data) = extract_send_payload_data(payload)?;
    let data = serde_json::to_string(&data).map_err(|_| AppError::Internal)?;

    let (password_hash, password_salt, password_iter) = if let Some(password) = password {
        let salt = new_salt_b64();
        let hash = hash_password(&password, &salt, SEND_PASSWORD_ITERATIONS)?;
        (Some(hash), Some(salt), Some(SEND_PASSWORD_ITERATIONS))
    } else {
        (
            existing.password_hash,
            existing.password_salt,
            existing.password_iter,
        )
    };

    db.prepare(
        "UPDATE sends SET type = ?1, name = ?2, notes = ?3, data = ?4, key = ?5,
         password_hash = ?6, password_salt = ?7, password_iter = ?8,
         max_access_count = ?9, updated_at = ?10, expiration_date = ?11,
         deletion_date = ?12, disabled = ?13, hide_email = ?14
         WHERE id = ?15 AND user_id = ?16",
    )
    .bind(&[
        send_type.into(),
        name.into(),
        notes
            .map(Into::into)
            .unwrap_or(worker::wasm_bindgen::JsValue::NULL),
        data.into(),
        key.into(),
        password_hash
            .map(Into::into)
            .unwrap_or(worker::wasm_bindgen::JsValue::NULL),
        password_salt
            .map(Into::into)
            .unwrap_or(worker::wasm_bindgen::JsValue::NULL),
        password_iter
            .map(Into::into)
            .unwrap_or(worker::wasm_bindgen::JsValue::NULL),
        max_access_count
            .map(Into::into)
            .unwrap_or(worker::wasm_bindgen::JsValue::NULL),
        now.into(),
        expiration_date
            .map(Into::into)
            .unwrap_or(worker::wasm_bindgen::JsValue::NULL),
        deletion_date.into(),
        (if disabled { 1 } else { 0 }).into(),
        hide_email
            .map(|value| if value { 1 } else { 0 })
            .map(Into::into)
            .unwrap_or(worker::wasm_bindgen::JsValue::NULL),
        send_id.into(),
        user_id.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct SendAccessTokenClaims {
    nbf: usize,
    exp: usize,
    iss: String,
    sub: String,
}

/// Create a signed JWT cookie value valid for `SEND_ACCESS_COOKIE_TTL_MINUTES`.
async fn generate_send_access_cookie(state: &Arc<AppState>) -> Result<String, AppError> {
    let jwt_keys = state.jwt_keys.clone();
    let now = Utc::now();
    let claims = SendAccessPassClaims {
        aud: "send_access".to_string(),
        iat: now.timestamp() as usize,
        exp: (now + chrono::Duration::minutes(SEND_ACCESS_COOKIE_TTL_MINUTES)).timestamp() as usize,
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(jwt_keys.access_secret.as_bytes()),
    )?;
    Ok(token)
}

/// Validate the signed cookie; returns `Ok(())` if valid.
async fn validate_send_access_cookie(state: &Arc<AppState>, token: &str) -> Result<(), AppError> {
    let jwt_keys = state.jwt_keys.clone();
    let mut validation = jsonwebtoken::Validation::default();
    validation.set_audience(&["send_access"]);
    validation.set_required_spec_claims(&["exp", "aud"]);
    jsonwebtoken::decode::<SendAccessPassClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(jwt_keys.access_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::Unauthorized("Invalid or expired send access pass".to_string()))?;
    Ok(())
}

/// Extract the `cf_send_pass` cookie from request headers.
fn extract_send_access_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .filter_map(|c| {
                    let mut parts = c.splitn(2, '=');
                    let name = parts.next()?.trim();
                    let value = parts.next()?.trim();
                    if name == SEND_ACCESS_COOKIE {
                        Some(value.to_string())
                    } else {
                        None
                    }
                })
                .next()
        })
}

/// Enforce Turnstile cookie on send-access endpoints.
/// Returns `Ok(())` if Turnstile is disabled or the cookie is valid.
async fn require_send_access_pass(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    if !turnstile_enabled(state) {
        return Ok(());
    }
    let token = extract_send_access_cookie(headers)
        .ok_or_else(|| AppError::Unauthorized("Turnstile verification required".to_string()))?;
    validate_send_access_cookie(state, &token).await
}

/// Build the Set-Cookie header value for the send-access pass (HttpOnly, backend use).
fn send_access_cookie_header(token: &str) -> String {
    format!(
        "{SEND_ACCESS_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        SEND_ACCESS_COOKIE_TTL_MINUTES * 60
    )
}

/// Build the Set-Cookie header for the frontend flag cookie (non-HttpOnly).
fn send_access_flag_cookie_header() -> String {
    format!(
        "{SEND_ACCESS_FLAG_COOKIE}=1; Path=/; Secure; SameSite=Lax; Max-Age={}",
        SEND_ACCESS_COOKIE_TTL_MINUTES * 60
    )
}

// ─── Send-verify endpoints ───

/// `GET /send-verify` – serves the Turnstile challenge page with the site key injected.
#[worker::send]
pub async fn send_verify_page(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let site_key = state
        .env
        .var("TURNSTILE_SITE_KEY")
        .map(|v| v.to_string())
        .unwrap_or_default();

    let html = include_str!("../../../static/send-verify.html").replace(
        "|| window.__TURNSTILE_SITE_KEY__",
        &format!("|| '{}'", site_key),
    );

    let mut response = Response::new(axum::body::Body::from(html));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    // Allow Turnstile scripts and frames
    response.headers_mut().insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; \
             frame-src https://challenges.cloudflare.com; \
             style-src 'self' 'unsafe-inline'; \
             connect-src 'self' https://challenges.cloudflare.com; \
             img-src 'self' data:",
        ),
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
pub struct SendVerifyPayload {
    token: String,
}

/// `POST /api/send-verify` – validate Turnstile token and issue a signed cookie.
#[worker::send]
pub async fn post_send_verify(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<SendVerifyPayload>,
) -> Result<Response, AppError> {
    let client_ip = request_client_ip(&headers);
    verify_turnstile_token(&state, &payload.token, client_ip.as_deref()).await?;

    let cookie_value = generate_send_access_cookie(&state).await?;
    let mut response = Response::new(axum::body::Body::from(
        serde_json::to_string(&json!({ "ok": true })).unwrap(),
    ));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    // Set the HttpOnly signed JWT cookie (for backend verification)
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&send_access_cookie_header(&cookie_value))
            .map_err(|_| AppError::Internal)?,
    );
    // Set the non-HttpOnly flag cookie (for frontend JS detection)
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&send_access_flag_cookie_header())
            .map_err(|_| AppError::Internal)?,
    );
    Ok(response)
}

/// Check that both D1 and R2 have at least 20% free space before allowing a file upload.
async fn check_storage_quota(
    db: &worker::D1Database,
    incoming_file_size: i64,
) -> Result<(), AppError> {
    // --- D1 check ---
    let d1_used: Option<i64> = db
        .prepare(
            "SELECT COALESCE(SUM(LENGTH(data)),0) \
             + (SELECT COALESCE(SUM(LENGTH(data)),0) FROM sends) \
             + (SELECT COALESCE(SUM(LENGTH(name)),0) FROM folders) \
             AS bytes FROM ciphers",
        )
        .bind(&[])?
        .first(Some("bytes"))
        .await
        .map_err(|_| AppError::Database)?;
    let d1_used = d1_used.unwrap_or(0);
    let d1_remaining = D1_MAX_BYTES - d1_used;
    let d1_threshold = (D1_MAX_BYTES as f64 * STORAGE_MIN_FREE_RATIO) as i64;
    if d1_remaining < d1_threshold {
        return Err(AppError::BadRequest(format!(
            "D1 storage nearly full: {remaining} remaining (threshold {threshold})",
            remaining = display_size(d1_remaining.max(0)),
            threshold = display_size(d1_threshold),
        )));
    }

    // --- R2 check ---
    let r2_used: Option<i64> = db
        .prepare("SELECT COALESCE(SUM(size), 0) AS bytes FROM send_files WHERE storage_type = 'r2'")
        .bind(&[])?
        .first(Some("bytes"))
        .await
        .map_err(|_| AppError::Database)?;
    let r2_used = r2_used.unwrap_or(0);
    let r2_after_upload = r2_used + incoming_file_size;
    let r2_remaining = R2_MAX_BYTES - r2_after_upload;
    let r2_threshold = (R2_MAX_BYTES as f64 * STORAGE_MIN_FREE_RATIO) as i64;
    if r2_remaining < r2_threshold {
        return Err(AppError::BadRequest(format!(
            "R2 storage nearly full: {remaining} remaining after upload (threshold {threshold})",
            remaining = display_size(r2_remaining.max(0)),
            threshold = display_size(r2_threshold),
        )));
    }

    Ok(())
}

async fn enforce_send_access_rate_limit(
    state: &Arc<AppState>,
    key: String,
) -> Result<(), AppError> {
    let limiter = match state.env.rate_limiter(SEND_ACCESS_RATE_LIMITER_BINDING) {
        Ok(l) => l,
        Err(_) => return Ok(()), // Skip rate limiting if binding is not configured
    };
    let outcome = limiter.limit(key).await.map_err(|_| AppError::Internal)?;
    if !outcome.success {
        return Err(AppError::TooManyRequests("Too many requests".to_string()));
    }
    Ok(())
}

fn display_size(bytes: i64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let kb = bytes as f64 / 1024.0;
    if kb < 1024.0 {
        return format!("{:.1} KB", kb);
    }
    let mb = kb / 1024.0;
    if mb < 1024.0 {
        return format!("{:.1} MB", mb);
    }
    let gb = mb / 1024.0;
    format!("{:.1} GB", gb)
}

fn hash_password(password: &str, salt_b64: &str, iterations: i32) -> Result<String, AppError> {
    let salt = general_purpose::STANDARD
        .decode(salt_b64)
        .map_err(|_| AppError::Internal)?;
    let iterations = u32::try_from(iterations).map_err(|_| AppError::Internal)?;
    if iterations == 0 {
        return Err(AppError::Internal);
    }
    let mut out = [0_u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut out);
    Ok(general_purpose::STANDARD.encode(out))
}

fn verify_password(
    password: &str,
    salt_b64: &str,
    stored_hash_b64: &str,
    iterations: Option<i32>,
) -> Result<bool, AppError> {
    let Some(iterations) = iterations.filter(|value| *value > 0) else {
        return Ok(false);
    };
    let candidate = hash_password(password, salt_b64, iterations)?;
    Ok(constant_time_eq(
        stored_hash_b64.as_bytes(),
        candidate.as_bytes(),
    ))
}

fn new_salt_b64() -> String {
    let mut bytes = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    general_purpose::STANDARD.encode(bytes)
}

async fn finish_send_mutation(
    db: &worker::D1Database,
    state: &Arc<AppState>,
    user_id: &str,
    send_id: &str,
    _revision_date: &str,
    update_type: UpdateType,
) -> Result<(), AppError> {
    let revision = db::update_user_revision(db, user_id).await?;
    notifications::publish_send_update_background(
        &state.ctx,
        state.env.clone(),
        update_type,
        user_id.to_string(),
        send_id.to_string(),
        revision,
    );
    Ok(())
}

fn extract_send_payload_data(mut data: SendData) -> Result<(i32, String, Value), AppError> {
    let send_type = data.r#type;
    let mut payload = match send_type {
        SEND_TYPE_TEXT => data
            .text
            .take()
            .ok_or_else(|| AppError::BadRequest("Missing text".to_string()))?,
        SEND_TYPE_FILE => data
            .file
            .take()
            .ok_or_else(|| AppError::BadRequest("Missing file".to_string()))?,
        _ => return Err(AppError::BadRequest("Invalid send type".to_string())),
    };

    if let Some(obj) = payload.as_object_mut() {
        obj.remove("response");
    }

    Ok((send_type, data.key, payload))
}

fn reject_unsupported_email_verification(data: &SendData) -> Result<(), AppError> {
    if data.emails.is_some() {
        return Err(AppError::BadRequest(
            "Sends with email verification are not supported".to_string(),
        ));
    }
    Ok(())
}

async fn get_send_by_id(
    db: &worker::D1Database,
    send_id: &str,
) -> Result<Option<SendDBModel>, AppError> {
    let value: Option<Value> = db
        .prepare("SELECT * FROM sends WHERE id = ?1")
        .bind(&[send_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    Ok(value.and_then(|v| serde_json::from_value::<SendDBModel>(v).ok()))
}

async fn get_send_by_id_and_user(
    db: &worker::D1Database,
    send_id: &str,
    user_id: &str,
) -> Result<Option<SendDBModel>, AppError> {
    let value: Option<Value> = db
        .prepare("SELECT * FROM sends WHERE id = ?1 AND user_id = ?2")
        .bind(&[send_id.into(), user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    Ok(value.and_then(|v| serde_json::from_value::<SendDBModel>(v).ok()))
}

async fn delete_send_files_from_r2(
    env: &worker::Env,
    db: &worker::D1Database,
    send_id: &str,
    user_id: &str,
) -> Result<(), AppError> {
    let file_rows: Vec<Value> = db
        .prepare(
            "SELECT r2_object_key, storage_type FROM send_files WHERE send_id = ?1 AND user_id = ?2",
        )
        .bind(&[send_id.into(), user_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let r2_keys = file_rows
        .iter()
        .filter(|row| {
            row.get("storage_type")
                .and_then(|value| value.as_str())
                .unwrap_or("d1_base64")
                == "r2"
        })
        .map(|row| {
            row.get("r2_object_key")
                .and_then(|value| value.as_str())
                .filter(|key| !key.is_empty())
                .map(str::to_string)
                .ok_or(AppError::Internal)
        })
        .collect::<Result<Vec<_>, _>>()?;

    if r2_keys.is_empty() {
        return Ok(());
    }
    let bucket = env
        .bucket(SEND_FILES_BUCKET_BINDING)
        .map_err(|_| AppError::Internal)?;
    for key in r2_keys {
        bucket.delete(key).await.map_err(|err| {
            log::error!(
                target: targets::API,
                "send R2 delete failed user_id={user_id} send_id={send_id}: {err:?}"
            );
            AppError::Internal
        })?;
    }
    Ok(())
}

pub(crate) async fn delete_user_send_files_from_r2(
    env: &worker::Env,
    db: &worker::D1Database,
    user_id: &str,
) -> Result<(), AppError> {
    let rows: Vec<Value> = db
        .prepare("SELECT id FROM sends WHERE user_id = ?1 AND type = ?2")
        .bind(&[user_id.into(), SEND_TYPE_FILE.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    for row in rows {
        let send_id = row
            .get("id")
            .and_then(Value::as_str)
            .ok_or(AppError::Database)?;
        delete_send_files_from_r2(env, db, send_id, user_id).await?;
    }
    Ok(())
}

pub(crate) async fn purge_expired_sends(env: &worker::Env) -> Result<usize, AppError> {
    let db = db::get_db(env)?;
    let now = now_rfc3339_millis();
    let rows: Vec<Value> = db
        .prepare("SELECT id, user_id, type FROM sends WHERE deletion_date <= ?1")
        .bind(&[now.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;

    let mut purged = 0;
    for row in rows {
        let send_id = row
            .get("id")
            .and_then(Value::as_str)
            .ok_or(AppError::Database)?;
        let user_id = row
            .get("user_id")
            .and_then(Value::as_str)
            .ok_or(AppError::Database)?;
        let send_type = row.get("type").and_then(Value::as_i64).unwrap_or_default() as i32;

        if send_type == SEND_TYPE_FILE
            && let Err(err) = delete_send_files_from_r2(env, &db, send_id, user_id).await
        {
            log::error!(
                target: targets::API,
                "expired Send cleanup retained metadata user_id={user_id} send_id={send_id}: {err}"
            );
            continue;
        }

        db.prepare("DELETE FROM sends WHERE id = ?1 AND user_id = ?2")
            .bind(&[send_id.into(), user_id.into()])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        db::update_user_revision(&db, user_id).await?;
        purged += 1;
    }
    Ok(purged)
}

async fn register_send_access(
    db: &worker::D1Database,
    send_id: &str,
) -> Result<Option<String>, AppError> {
    let revision = now_rfc3339_millis();
    let result = db
        .prepare(
            "UPDATE sends
             SET access_count = access_count + 1, updated_at = ?1
             WHERE id = ?2
               AND (max_access_count IS NULL OR access_count < max_access_count)",
        )
        .bind(&[revision.clone().into(), send_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    let changed = result.meta()?.and_then(|meta| meta.changes).unwrap_or(0);
    Ok((changed == 1).then_some(revision))
}

async fn get_creator_identifier(
    db: &worker::D1Database,
    send: &SendDBModel,
) -> Result<Option<String>, AppError> {
    if send.hide_email.unwrap_or(false) {
        return Ok(None);
    }
    let email: Option<String> = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[send.user_id.clone().into()])?
        .first(Some("email"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(email)
}

fn validate_send_lifetime(send: &SendDBModel) -> Result<(), AppError> {
    if send.disabled {
        return Err(AppError::NotFound("Send not found".to_string()));
    }

    let now = Utc::now();
    if let Some(exp) = send.expiration_date.as_deref() {
        let exp = parse_rfc3339(exp)?;
        if now >= exp {
            return Err(AppError::NotFound("Send not found".to_string()));
        }
    }

    let del = parse_rfc3339(&send.deletion_date)?;
    if now >= del {
        return Err(AppError::NotFound("Send not found".to_string()));
    }

    Ok(())
}

fn validate_send_access(send: &SendDBModel) -> Result<(), AppError> {
    validate_send_lifetime(send)?;

    if let Some(max_access_count) = send.max_access_count
        && send.access_count >= max_access_count
    {
        return Err(AppError::NotFound("Send not found".to_string()));
    }

    Ok(())
}

fn validate_send_password(send: &SendDBModel, password: Option<String>) -> Result<(), AppError> {
    let Some(stored_hash_b64) = send.password_hash.as_deref() else {
        log::debug!(target: targets::AUTH, "send.password_check.skip send_id={} reason=no_password_hash", send.id);
        return Ok(());
    };
    let Some(stored_salt_b64) = send.password_salt.as_deref() else {
        log::error!(target: targets::AUTH, "send.password_check.error send_id={} reason=missing_salt", send.id);
        return Err(AppError::Internal);
    };

    let Some(password) = password else {
        log::warn!(target: targets::AUTH, "send.password_check.fail send_id={} reason=password_not_provided", send.id);
        return Err(AppError::Unauthorized("Password not provided".to_string()));
    };
    if !verify_password(
        &password,
        stored_salt_b64,
        stored_hash_b64,
        send.password_iter,
    )? {
        log::warn!(target: targets::AUTH, "send.password_check.fail send_id={} reason=password_mismatch", send.id);
        return Err(AppError::BadRequest("Invalid password".to_string()));
    }
    log::debug!(target: targets::AUTH, "send.password_check.ok send_id={}", send.id);
    Ok(())
}

fn send_access_token_error(
    status: StatusCode,
    error: &'static str,
    error_type: &'static str,
    description: &'static str,
) -> Response {
    (
        status,
        Json(json!({
            "kind": "expected_server",
            "error": error,
            "error_description": description,
            "send_access_error_type": error_type,
        })),
    )
        .into_response()
}

pub async fn issue_send_access_token(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    access_id: &str,
    password_hash_b64: Option<String>,
) -> Result<Response, AppError> {
    require_send_access_pass(state, headers).await?;

    let client_ip = request_client_ip(headers);
    enforce_send_access_rate_limit(
        state,
        format!(
            "send_token:{}:{}",
            access_id,
            client_ip.as_deref().unwrap_or("unknown")
        ),
    )
    .await?;

    let Some(send_id) = uuid_from_access_id(access_id) else {
        return Ok(send_access_token_error(
            StatusCode::NOT_FOUND,
            "invalid_grant",
            "send_id_invalid",
            "Invalid Send identifier",
        ));
    };

    let db = db::get_db(&state.env)?;
    let Some(send) = get_send_by_id(&db, &send_id).await? else {
        return Ok(send_access_token_error(
            StatusCode::NOT_FOUND,
            "invalid_grant",
            "send_id_invalid",
            "Invalid Send identifier",
        ));
    };

    if validate_send_access(&send).is_err() {
        return Ok(send_access_token_error(
            StatusCode::NOT_FOUND,
            "invalid_grant",
            "send_id_invalid",
            "Send is unavailable",
        ));
    }

    if let Some(stored_hash_b64) = send.password_hash.as_deref() {
        let Some(stored_salt_b64) = send.password_salt.as_deref() else {
            log::error!(target: targets::AUTH, "send.token.error send_id={} reason=missing_salt", send.id);
            return Err(AppError::Internal);
        };
        let Some(password_hash_b64) = password_hash_b64 else {
            return Ok(send_access_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "password_hash_b64_required",
                "Password is required",
            ));
        };
        if !verify_password(
            &password_hash_b64,
            stored_salt_b64,
            stored_hash_b64,
            send.password_iter,
        )? {
            log::warn!(
                target: targets::AUTH,
                "send.token.denied send_id={} reason=password_mismatch ip={}",
                send.id,
                client_ip.as_deref().unwrap_or("unknown")
            );
            return Ok(send_access_token_error(
                StatusCode::NOT_FOUND,
                "invalid_grant",
                "password_hash_b64_invalid",
                "Invalid password",
            ));
        }
    }

    let Some(revision) = register_send_access(&db, &send.id).await? else {
        return Ok(send_access_token_error(
            StatusCode::NOT_FOUND,
            "invalid_grant",
            "send_id_invalid",
            "Send has reached its maximum access count",
        ));
    };
    finish_send_mutation(
        &db,
        state,
        &send.user_id,
        &send.id,
        &revision,
        UpdateType::SyncSendUpdate,
    )
    .await?;

    let now = Utc::now();
    let expires_in = chrono::Duration::minutes(SEND_ACCESS_TOKEN_TTL_MINUTES);
    let claims = SendAccessTokenClaims {
        nbf: now.timestamp() as usize,
        exp: (now + expires_in).timestamp() as usize,
        iss: SEND_ACCESS_TOKEN_ISSUER.to_string(),
        sub: send.id.clone(),
    };
    let access_token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(state.jwt_keys.access_secret.as_bytes()),
    )?;

    log::info!(
        target: targets::AUTH,
        "send.token.success send_id={} ip={}",
        send.id,
        client_ip.as_deref().unwrap_or("unknown")
    );

    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": expires_in.num_seconds(),
        "token_type": "Bearer",
        "scope": "api.send.access",
    }))
    .into_response())
}

fn send_id_from_access_token(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<String, AppError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Unauthorized("No access token provided".to_string()))?;

    let token_data = jsonwebtoken::decode::<SendAccessTokenClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(state.jwt_keys.access_secret.as_bytes()),
        &jsonwebtoken::Validation::default(),
    )
    .map_err(|_| AppError::Unauthorized("Invalid Send access token".to_string()))?;

    if token_data.claims.iss != SEND_ACCESS_TOKEN_ISSUER {
        return Err(AppError::Unauthorized(
            "Invalid Send access token".to_string(),
        ));
    }

    Ok(token_data.claims.sub)
}

#[worker::send]
pub async fn get_sends(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let rows: Vec<Value> = db
        .prepare("SELECT * FROM sends WHERE user_id = ?1 ORDER BY updated_at DESC")
        .bind(&[claims.sub.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;

    let data = rows
        .into_iter()
        .filter_map(|v| serde_json::from_value::<SendDBModel>(v).ok())
        .map(|s| send_to_json(&s))
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "data": data,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn get_send(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(send_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let send = get_send_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;
    Ok(Json(send_to_json(&send)))
}

#[worker::send]
pub async fn delete_send(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(send_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let owned = get_send_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;

    // 记录删除请求的详细信息
    log::info!(
        target: targets::API,
        "send.delete.request user_id={} send_id={} type={} deletion_date={} expiration_date={:?} access_count={} max_access_count={:?} disabled={}",
        claims.sub,
        send_id,
        owned.r#type,
        owned.deletion_date,
        owned.expiration_date,
        owned.access_count,
        owned.max_access_count,
        owned.disabled
    );

    if owned.r#type == SEND_TYPE_FILE {
        // R2 deletion is part of the operation. Keep D1 metadata intact on
        // failure so the operation can be retried without orphaning objects.
        delete_send_files_from_r2(&state.env, &db, &send_id, &claims.sub).await?;

        query!(
            &db,
            "DELETE FROM send_files WHERE send_id = ?1 AND user_id = ?2",
            send_id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

        log::info!(
            target: targets::API,
            "send.delete.db.send_files user_id={} send_id={}",
            claims.sub,
            send_id
        );
    }

    query!(
        &db,
        "DELETE FROM sends WHERE id = ?1 AND user_id = ?2",
        send_id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    log::info!(
        target: targets::API,
        "send.delete.db.sends user_id={} send_id={}",
        claims.sub,
        send_id
    );

    let revision = db::now_rfc3339_millis();
    finish_send_mutation(
        &db,
        &state,
        &claims.sub,
        &send_id,
        &revision,
        UpdateType::SyncSendDelete,
    )
    .await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::SendDelete,
        NotifyContext {
            user_id: Some(claims.sub.clone()),
            user_email: Some(claims.email.clone()),
            send_id: Some(send_id.clone()),
            detail: Some(format!("type={}", owned.r#type)),
            meta,
            ..Default::default()
        },
    );

    log::info!(
        target: targets::API,
        "send.delete.success user_id={} send_id={} type={}",
        claims.sub,
        send_id,
        owned.r#type
    );

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_send(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<SendData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    reject_unsupported_email_verification(&payload)?;
    enforce_organization_send_policies(&db, &claims.sub, payload.hide_email).await?;

    if payload.r#type == SEND_TYPE_FILE {
        return Err(AppError::BadRequest(
            "File sends should use /api/sends/file".to_string(),
        ));
    }

    log::info!(
        target: targets::API,
        "send.create.request user_id={} type={} has_password={} has_turnstile_field=false",
        claims.sub,
        payload.r#type,
        payload
            .password
            .as_deref()
            .map(str::trim)
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    );

    let name = payload.name.clone();
    let notes = payload.notes.clone();
    let password = payload.password.clone();
    let max_access_count = payload.max_access_count;
    let expiration_date = payload.expiration_date.clone();
    let deletion_date = payload.deletion_date.clone();
    validate_deletion_date(&deletion_date)?;
    let disabled = payload.disabled;
    let hide_email = payload.hide_email;

    let (send_type, key, data_value) = extract_send_payload_data(payload)?;
    let send_id = Uuid::new_v4().to_string();
    let now = now_rfc3339_millis();

    let password_salt = password
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(|_| new_salt_b64());
    let password_hash = match (password.as_deref(), password_salt.as_deref()) {
        (Some(p), Some(salt)) if !p.trim().is_empty() => {
            Some(hash_password(p, salt, SEND_PASSWORD_ITERATIONS)?)
        }
        _ => None,
    };
    let password_iter = password_hash.as_ref().map(|_| SEND_PASSWORD_ITERATIONS);

    let data_str = serde_json::to_string(&data_value).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "INSERT INTO sends (id, user_id, organization_id, type, name, notes, data, key, password_hash, password_salt, password_iter, max_access_count, access_count, created_at, updated_at, expiration_date, deletion_date, disabled, hide_email)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, ?13, ?14, ?15, ?16, ?17)",
        send_id,
        claims.sub,
        send_type,
        name,
        notes,
        data_str,
        key,
        password_hash,
        password_salt,
        password_iter,
        max_access_count,
        now,
        now,
        expiration_date,
        deletion_date,
        if disabled { 1 } else { 0 },
        hide_email.map(|b| if b { 1 } else { 0 })
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let send = get_send_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::Internal)?;

    finish_send_mutation(
        &db,
        &state,
        &claims.sub,
        &send_id,
        &send.updated_at,
        UpdateType::SyncSendCreate,
    )
    .await?;

    log::info!(
        target: targets::API,
        "send.create.success user_id={} send_id={} type={} stored_has_password={}",
        claims.sub,
        send_id,
        send_type,
        send.password_hash.as_deref().is_some()
    );

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::SendCreate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            send_id: Some(send_id),
            detail: Some(format!("type={send_type}")),
            meta,
            ..Default::default()
        },
    );
    Ok(Json(send_to_json(&send)))
}

#[worker::send]
pub async fn post_send_file_legacy(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let file_id = Uuid::new_v4().to_string();
    let send_id = Uuid::new_v4().to_string();
    let object_key = format!("sends/{}/{}/{}", claims.sub, send_id, file_id);
    let bucket = state
        .env
        .bucket(SEND_FILES_BUCKET_BINDING)
        .map_err(|_| AppError::Internal)?;
    let committed = async {
        let mut model = None;
        let mut encrypted_file_name = None;
        let mut uploaded_size = None;
        while let Some(mut field) = multipart
            .next_field()
            .await
            .map_err(|_| AppError::BadRequest("Invalid multipart".to_string()))?
        {
            match field.name() {
                Some("model") => {
                    model = Some(field.text().await.map_err(|_| {
                        AppError::BadRequest("Invalid send model".to_string())
                    })?);
                }
                Some("data") => {
                    if uploaded_size.is_some() {
                        return Err(AppError::BadRequest(
                            "Multiple file data fields are not supported".to_string(),
                        ));
                    }
                    encrypted_file_name = field.file_name().map(str::to_string);
                    uploaded_size = Some(r2_file::upload_field(&bucket, &object_key, &mut field).await?);
                }
                _ => {}
            }
        }

        let model = model.ok_or_else(|| AppError::BadRequest("Missing send model".to_string()))?;
        let payload: SendData = serde_json::from_str(&model)
            .map_err(|_| AppError::BadRequest("Invalid send model".to_string()))?;
        enforce_organization_send_policies(&db, &claims.sub, payload.hide_email).await?;
        reject_unsupported_email_verification(&payload)?;
        if payload.r#type != SEND_TYPE_FILE {
            return Err(AppError::BadRequest(
                "Send content is not a file".to_string(),
            ));
        }
        validate_deletion_date(&payload.deletion_date)?;
        let encrypted_file_name = encrypted_file_name
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::BadRequest("No filename provided".to_string()))?;
        let file_length = uploaded_size
            .ok_or_else(|| AppError::BadRequest("Missing file data".to_string()))?
            as i64;
        check_storage_quota(&db, file_length).await?;

        let name = payload.name.clone();
        let notes = payload.notes.clone();
        let password = payload.password.clone();
        let max_access_count = payload.max_access_count;
        let expiration_date = payload.expiration_date.clone();
        let deletion_date = payload.deletion_date.clone();
        let disabled = payload.disabled;
        let hide_email = payload.hide_email;
        let (send_type, key, mut data_value) = extract_send_payload_data(payload)?;
        if let Some(obj) = data_value.as_object_mut() {
            obj.insert("id".to_string(), Value::String(file_id.clone()));
            obj.insert("size".to_string(), Value::Number(file_length.into()));
            obj.insert(
                "sizeName".to_string(),
                Value::String(display_size(file_length)),
            );
        }

        let now = now_rfc3339_millis();
        let data_str = serde_json::to_string(&data_value).map_err(|_| AppError::Internal)?;
        let password_salt = password
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(|_| new_salt_b64());
        let password_hash = match (password.as_deref(), password_salt.as_deref()) {
            (Some(password), Some(salt)) => {
                Some(hash_password(password, salt, SEND_PASSWORD_ITERATIONS)?)
            }
            _ => None,
        };
        let password_iter = password_hash.as_ref().map(|_| SEND_PASSWORD_ITERATIONS);
        let send_stmt = query!(
            &db,
            "INSERT INTO sends (id, user_id, organization_id, type, name, notes, data, key, password_hash, password_salt, password_iter, max_access_count, access_count, created_at, updated_at, expiration_date, deletion_date, disabled, hide_email)
             VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, ?13, ?14, ?15, ?16, ?17)",
            send_id,
            claims.sub,
            send_type,
            name,
            notes,
            data_str,
            key,
            password_hash,
            password_salt,
            password_iter,
            max_access_count,
            now,
            now,
            expiration_date,
            deletion_date,
            if disabled { 1 } else { 0 },
            hide_email.map(|value| if value { 1 } else { 0 })
        )
        .map_err(|_| AppError::Database)?;
        let file_stmt = query!(
            &db,
            "INSERT INTO send_files (id, send_id, user_id, file_name, size, mime, data_base64, r2_object_key, storage_type, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, 'r2', ?7, ?8)",
            file_id,
            send_id,
            claims.sub,
            encrypted_file_name,
            file_length as f64,
            object_key,
            now,
            now
        )
        .map_err(|_| AppError::Database)?;
        db.batch(vec![send_stmt, file_stmt])
            .await
            .map_err(|_| AppError::Database)?;
        Ok::<_, AppError>((send_type, encrypted_file_name))
    }
    .await;
    let (send_type, encrypted_file_name) = match committed {
        Ok(result) => result,
        Err(err) => {
            let _ = bucket.delete(object_key).await;
            return Err(err);
        }
    };

    let send = get_send_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or(AppError::Internal)?;
    finish_send_mutation(
        &db,
        &state,
        &claims.sub,
        &send_id,
        &send.updated_at,
        UpdateType::SyncSendCreate,
    )
    .await?;
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::SendCreate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            send_id: Some(send_id),
            detail: Some(format!("type={send_type}, file={encrypted_file_name}")),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );
    Ok(Json(send_to_json(&send)))
}

#[worker::send]
pub async fn put_send(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(send_id): Path<String>,
    Json(raw_payload): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<missing>");
    let raw_password = raw_payload.get("password");
    let has_password_key = raw_payload.get("password").is_some();
    let raw_password_kind = match raw_password {
        Some(Value::String(_)) => "string",
        Some(Value::Null) => "null",
        Some(_) => "non_string",
        None => "missing",
    };
    let raw_password_len = raw_password
        .and_then(|v| v.as_str())
        .map(|s| s.len())
        .unwrap_or(0);
    log::info!(
        target: targets::API,
        "send.update.raw send_id={} content_type={} has_password_key={} password_kind={} password_len={}",
        send_id,
        content_type,
        has_password_key,
        raw_password_kind,
        raw_password_len
    );

    let payload: SendData = serde_json::from_value(raw_payload)
        .map_err(|_| AppError::BadRequest("Invalid send payload".to_string()))?;
    reject_unsupported_email_verification(&payload)?;
    enforce_organization_send_policies(&db, &claims.sub, payload.hide_email).await?;

    let existing = get_send_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;

    if existing.r#type != payload.r#type {
        return Err(AppError::BadRequest("Cannot change send type".to_string()));
    }

    log::info!(
        target: targets::API,
        "send.update.request user_id={} send_id={} type={} has_password={}",
        claims.sub,
        send_id,
        payload.r#type,
        payload
            .password
            .as_deref()
            .map(str::trim)
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    );

    let name = payload.name.clone();
    let notes = payload.notes.clone();
    let password = payload.password.clone();
    let max_access_count = payload.max_access_count;
    let expiration_date = payload.expiration_date.clone();
    let deletion_date = payload.deletion_date.clone();
    validate_deletion_date(&deletion_date)?;
    let disabled = payload.disabled;
    let hide_email = payload.hide_email;

    let key = payload.key.clone();
    let data_str = if payload.r#type == SEND_TYPE_TEXT {
        let mut text = payload
            .text
            .ok_or_else(|| AppError::BadRequest("Missing text".to_string()))?;
        if let Some(obj) = text.as_object_mut() {
            obj.remove("response");
        }
        serde_json::to_string(&text).map_err(|_| AppError::Internal)?
    } else {
        existing.data.clone()
    };

    let now = now_rfc3339_millis();

    let mut password_hash = existing.password_hash.clone();
    let mut password_salt = existing.password_salt.clone();
    let mut password_iter = existing.password_iter;

    if let Some(password) = password.as_deref() {
        let salt = new_salt_b64();
        let hash = hash_password(password, &salt, SEND_PASSWORD_ITERATIONS)?;
        password_hash = Some(hash);
        password_salt = Some(salt);
        password_iter = Some(SEND_PASSWORD_ITERATIONS);
    }

    log::info!(
        target: targets::API,
        "send.update.password_apply send_id={} has_password_key={} apply_new_password={} keep_existing_password={}",
        send_id,
        has_password_key,
        password.as_deref().is_some(),
        password.as_deref().is_none()
    );

    query!(
        &db,
        "UPDATE sends
         SET name = ?1,
             notes = ?2,
             data = ?3,
             key = ?4,
             password_hash = ?5,
             password_salt = ?6,
             password_iter = ?7,
             max_access_count = ?8,
             updated_at = ?9,
             expiration_date = ?10,
             deletion_date = ?11,
             disabled = ?12,
             hide_email = ?13
         WHERE id = ?14 AND user_id = ?15",
        name,
        notes,
        data_str,
        key,
        password_hash,
        password_salt,
        password_iter,
        max_access_count,
        now,
        expiration_date,
        deletion_date,
        if disabled { 1 } else { 0 },
        hide_email.map(|b| if b { 1 } else { 0 }),
        send_id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let send = get_send_by_id_and_user(&db, &existing.id, &existing.user_id)
        .await?
        .ok_or_else(|| AppError::Internal)?;

    finish_send_mutation(
        &db,
        &state,
        &existing.user_id,
        &existing.id,
        &send.updated_at,
        UpdateType::SyncSendUpdate,
    )
    .await?;

    log::info!(
        target: targets::API,
        "send.update.success user_id={} send_id={} type={} stored_has_password={}",
        existing.user_id,
        existing.id,
        existing.r#type,
        send.password_hash.as_deref().is_some()
    );

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::SendCreate,
        NotifyContext {
            user_id: Some(existing.user_id),
            user_email: Some(claims.email),
            send_id: Some(existing.id),
            detail: Some(format!("type={}", existing.r#type)),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(send_to_json(&send)))
}

#[worker::send]
pub async fn put_remove_send_password(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(send_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let existing = get_send_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;

    let now = now_rfc3339_millis();
    query!(
        &db,
        "UPDATE sends
         SET password_hash = NULL,
             password_salt = NULL,
             password_iter = NULL,
             updated_at = ?1
         WHERE id = ?2 AND user_id = ?3",
        now,
        send_id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let send = get_send_by_id_and_user(&db, &existing.id, &existing.user_id)
        .await?
        .ok_or_else(|| AppError::Internal)?;

    finish_send_mutation(
        &db,
        &state,
        &existing.user_id,
        &existing.id,
        &send.updated_at,
        UpdateType::SyncSendUpdate,
    )
    .await?;

    log::info!(
        target: targets::API,
        "send.remove_password.success user_id={} send_id={}",
        existing.user_id,
        existing.id
    );

    Ok(Json(send_to_json(&send)))
}

#[worker::send]
pub async fn post_send_file_v2(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SendData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    reject_unsupported_email_verification(&payload)?;
    enforce_organization_send_policies(&db, &claims.sub, payload.hide_email).await?;

    if payload.r#type != SEND_TYPE_FILE {
        return Err(AppError::BadRequest(
            "Send content is not a file".to_string(),
        ));
    }

    log::info!(
        target: targets::API,
        "send.create_file.request user_id={} type={} file_length={}",
        claims.sub,
        payload.r#type,
        payload.file_length.unwrap_or(-1)
    );

    let payload = payload;
    let file_length = payload
        .file_length
        .ok_or_else(|| AppError::BadRequest("Invalid send length".to_string()))?;
    r2_file::validate_declared_size(file_length, "Send")?;

    // Reject early if D1 or R2 is nearly full
    check_storage_quota(&db, file_length).await?;

    let name = payload.name.clone();
    let notes = payload.notes.clone();
    let password = payload.password.clone();
    let max_access_count = payload.max_access_count;
    let expiration_date = payload.expiration_date.clone();
    let deletion_date = payload.deletion_date.clone();
    validate_deletion_date(&deletion_date)?;
    let disabled = payload.disabled;
    let hide_email = payload.hide_email;

    let (send_type, key, mut data_value) = extract_send_payload_data(payload)?;

    let file_id = Uuid::new_v4().to_string();
    if let Some(obj) = data_value.as_object_mut() {
        obj.insert("id".to_string(), Value::String(file_id.clone()));
        obj.insert("size".to_string(), Value::Number(file_length.into()));
        obj.insert(
            "sizeName".to_string(),
            Value::String(display_size(file_length)),
        );
    }

    let send_id = Uuid::new_v4().to_string();
    let now = now_rfc3339_millis();
    let data_str = serde_json::to_string(&data_value).map_err(|_| AppError::Internal)?;
    let object_key = format!("sends/{}/{}/{}", claims.sub, send_id, file_id);
    let password_salt = password
        .as_deref()
        .filter(|password| !password.trim().is_empty())
        .map(|_| new_salt_b64());
    let password_hash = match (password.as_deref(), password_salt.as_deref()) {
        (Some(password), Some(salt)) => {
            Some(hash_password(password, salt, SEND_PASSWORD_ITERATIONS)?)
        }
        _ => None,
    };
    let password_iter = password_hash.as_ref().map(|_| SEND_PASSWORD_ITERATIONS);

    query!(
        &db,
        "INSERT INTO sends (id, user_id, organization_id, type, name, notes, data, key, password_hash, password_salt, password_iter, max_access_count, access_count, created_at, updated_at, expiration_date, deletion_date, disabled, hide_email)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, ?13, ?14, ?15, ?16, ?17)",
        send_id,
        claims.sub,
        send_type,
        name,
        notes,
        data_str,
        key,
        password_hash,
        password_salt,
        password_iter,
        max_access_count,
        now,
        now,
        expiration_date,
        deletion_date,
        if disabled { 1 } else { 0 },
        hide_email.map(|b| if b { 1 } else { 0 })
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    query!(
        &db,
        "INSERT INTO send_files (id, send_id, user_id, file_name, size, mime, data_base64, r2_object_key, storage_type, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, ?7, ?8, ?9)",
        file_id,
        send_id,
        claims.sub,
        data_value
            .get("fileName")
            .and_then(|v| v.as_str())
            .unwrap_or("file")
            .to_string(),
        file_length as f64,
        object_key,
        "r2",
        now,
        now
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    // Vaultwarden persists the placeholder Send and advances the user's
    // revision here, but emits SyncSendCreate only after the file upload.
    db::update_user_revision(&db, &claims.sub).await?;

    let send = get_send_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::Internal)?;

    log::info!(
        target: targets::API,
        "send.create_file.success user_id={} send_id={} file_id={} object_key={}",
        claims.sub,
        send_id,
        file_id,
        object_key
    );

    Ok(Json(json!({
        "fileUploadType": 0,
        "object": "send-fileUpload",
        "url": format!("/sends/{}/file/{}", send_id, file_id),
        "sendResponse": send_to_json(&send)
    })))
}

#[worker::send]
pub async fn post_send_file_v2_data(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((send_id, file_id)): Path<(String, String)>,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let send = get_send_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| {
            AppError::NotFound("Send not found. Unable to save the file.".to_string())
        })?;
    if send.r#type != SEND_TYPE_FILE {
        return Err(AppError::BadRequest(
            "Send content is not a file".to_string(),
        ));
    }

    let file_row: Option<Value> = db
        .prepare("SELECT size, file_name, r2_object_key, storage_type FROM send_files WHERE id = ?1 AND send_id = ?2 AND user_id = ?3 LIMIT 1")
        .bind(&[file_id.clone().into(), send_id.clone().into(), claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let file_row = file_row.ok_or_else(|| {
        AppError::NotFound("Send not found. Unable to save the file.".to_string())
    })?;
    let size = file_row
        .get("size")
        .and_then(|v| v.as_i64())
        .ok_or(AppError::Internal)?;
    r2_file::validate_declared_size(size, "Send")?;
    let object_key = file_row
        .get("r2_object_key")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Internal)?
        .to_string();
    let storage_type = file_row
        .get("storage_type")
        .and_then(|v| v.as_str())
        .unwrap_or("d1_base64");
    if storage_type != "r2" {
        return Err(AppError::BadRequest(
            "Send storage backend mismatch".to_string(),
        ));
    }
    let file_name = file_row
        .get("file_name")
        .and_then(Value::as_str)
        .unwrap_or("file")
        .to_string();

    let now = now_rfc3339_millis();
    let bucket = state
        .env
        .bucket(SEND_FILES_BUCKET_BINDING)
        .map_err(|_| AppError::Internal)?;

    let mut uploaded = false;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::BadRequest("Invalid multipart".to_string()))?
    {
        let name = field.name().unwrap_or("").to_string();
        if name != "data" {
            continue;
        }

        let uploaded_file_name = field
            .file_name()
            .ok_or_else(|| AppError::BadRequest("Send file name is not provided".to_string()))?;
        let is_cli = headers
            .get("device-type")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<i32>().ok())
            .is_some_and(|device_type| (23..=25).contains(&device_type));
        if uploaded_file_name != file_name && !(is_cli && file_name.ends_with(uploaded_file_name)) {
            return Err(AppError::BadRequest(format!(
                "Send file name does not match. Expected '{file_name}' got '{uploaded_file_name}'"
            )));
        }

        let actual_size = r2_file::upload_field(&bucket, &object_key, &mut field).await?;
        uploaded = true;
        if actual_size != size as u64 {
            let _ = bucket.delete(object_key.clone()).await;
            return Err(AppError::BadRequest("Uploaded size mismatch".to_string()));
        }
        let update_result: Result<(), AppError> = async {
            query!(
                &db,
                "UPDATE send_files SET updated_at = ?1 WHERE id = ?2 AND send_id = ?3 AND user_id = ?4",
                now,
                file_id,
                send_id,
                claims.sub
            )
            .map_err(|_| AppError::Database)?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
            Ok(())
        }
        .await;
        if update_result.is_err() {
            let _ = bucket.delete(object_key.clone()).await;
            return Err(AppError::Database);
        }

        break;
    }

    if !uploaded {
        return Err(AppError::BadRequest("Missing file data".to_string()));
    }

    query!(
        &db,
        "UPDATE sends SET updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        now,
        send_id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    finish_send_mutation(
        &db,
        &state,
        &claims.sub,
        &send_id,
        &now,
        UpdateType::SyncSendCreate,
    )
    .await?;

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::SendCreate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            send_id: Some(send_id),
            detail: Some(format!("type={SEND_TYPE_FILE}, file={file_name}")),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_access(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let send_id = send_id_from_access_token(&state, &headers)?;
    let db = db::get_db(&state.env)?;
    let send = get_send_by_id(&db, &send_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;
    validate_send_lifetime(&send)?;
    let creator_identifier = get_creator_identifier(&db, &send).await?;

    log::info!(target: targets::AUTH, "send.access_token.success send_id={} type={}", send.id, send.r#type);
    Ok(Json(send_to_json_access(&send, creator_identifier)))
}

#[worker::send]
pub async fn post_access_legacy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(access_id): Path<String>,
    Json(payload): Json<SendAccessData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    let client_ip = request_client_ip(&headers);
    log::info!(
        target: targets::AUTH,
        "send.access.request access_id={} ip={} has_password_payload={} has_turnstile_cookie={}",
        access_id,
        client_ip.as_deref().unwrap_or("unknown"),
        payload.password.as_deref().map(str::trim).map(|s| !s.is_empty()).unwrap_or(false),
        extract_send_access_cookie(&headers).is_some()
    );
    // Require Turnstile send-access pass (cookie set by /send-verify flow)
    require_send_access_pass(&state, &headers).await?;
    enforce_send_access_rate_limit(
        &state,
        format!(
            "send_access:{}:{}",
            access_id,
            client_ip.as_deref().unwrap_or("unknown")
        ),
    )
    .await?;

    let send_id = uuid_from_access_id(&access_id)
        .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;
    let send = get_send_by_id(&db, &send_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;

    log::info!(
        target: targets::AUTH,
        "send.access.loaded send_id={} type={} stored_has_password={}",
        send.id,
        send.r#type,
        send.password_hash.as_deref().is_some()
    );

    validate_send_access(&send)?;
    validate_send_password(&send, payload.password)?;

    if send.r#type == SEND_TYPE_TEXT {
        let revision = register_send_access(&db, &send.id)
            .await?
            .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;
        finish_send_mutation(
            &db,
            &state,
            &send.user_id,
            &send.id,
            &revision,
            UpdateType::SyncSendUpdate,
        )
        .await?;
    }

    let creator_identifier = get_creator_identifier(&db, &send).await?;
    log::info!(target: targets::AUTH, "send.access.success send_id={} type={}", send.id, send.r#type);
    Ok(Json(send_to_json_access(&send, creator_identifier)))
}

#[worker::send]
pub async fn post_access_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let send_id = send_id_from_access_token(&state, &headers)?;
    let db = db::get_db(&state.env)?;
    let send = get_send_by_id(&db, &send_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;
    validate_send_lifetime(&send)?;

    let file_exists: Option<i64> = db
        .prepare("SELECT 1 AS ok FROM send_files WHERE id = ?1 AND send_id = ?2 LIMIT 1")
        .bind(&[file_id.clone().into(), send.id.clone().into()])?
        .first(Some("ok"))
        .await
        .map_err(|_| AppError::Database)?;
    if file_exists.is_none() {
        return Err(AppError::NotFound("Send not found".to_string()));
    }

    let token = generate_download_token(&state, &send.id, &file_id).await?;
    let url = state.public_url(&format!("/api/sends/{}/{file_id}?t={token}", send.id));

    log::info!(target: targets::AUTH, "send.access_file_token.success send_id={} file_id={}", send.id, file_id);
    Ok(Json(json!({
        "object": "send-fileDownload",
        "id": file_id,
        "url": url
    })))
}

#[worker::send]
pub async fn post_access_file_legacy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((send_id, file_id)): Path<(String, String)>,
    Json(payload): Json<SendAccessData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    let client_ip = request_client_ip(&headers);
    log::info!(
        target: targets::AUTH,
        "send.access_file.request send_id={} file_id={} ip={} has_password_payload={} has_turnstile_cookie={}",
        send_id,
        file_id,
        client_ip.as_deref().unwrap_or("unknown"),
        payload.password.as_deref().map(str::trim).map(|s| !s.is_empty()).unwrap_or(false),
        extract_send_access_cookie(&headers).is_some()
    );
    // Require Turnstile send-access pass (cookie set by the /send-verify flow)
    require_send_access_pass(&state, &headers).await?;
    enforce_send_access_rate_limit(
        &state,
        format!(
            "send_access_file:{}:{}:{}",
            send_id,
            file_id,
            client_ip.as_deref().unwrap_or("unknown")
        ),
    )
    .await?;

    let send = get_send_by_id(&db, &send_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;

    log::info!(
        target: targets::AUTH,
        "send.access_file.loaded send_id={} type={} stored_has_password={}",
        send.id,
        send.r#type,
        send.password_hash.as_deref().is_some()
    );

    validate_send_access(&send)?;
    validate_send_password(&send, payload.password)?;

    let file_exists: Option<i64> = db
        .prepare("SELECT 1 AS ok FROM send_files WHERE id = ?1 AND send_id = ?2 LIMIT 1")
        .bind(&[file_id.clone().into(), send_id.clone().into()])?
        .first(Some("ok"))
        .await
        .map_err(|_| AppError::Database)?;
    if file_exists.is_none() {
        return Err(AppError::NotFound("Send not found".to_string()));
    }

    let revision = register_send_access(&db, &send.id)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;
    finish_send_mutation(
        &db,
        &state,
        &send.user_id,
        &send.id,
        &revision,
        UpdateType::SyncSendUpdate,
    )
    .await?;

    let token = generate_download_token(&state, &send_id, &file_id).await?;
    let url = state.public_url(&format!("/api/sends/{send_id}/{file_id}?t={token}"));

    log::info!(target: targets::AUTH, "send.access_file.success send_id={} file_id={}", send_id, file_id);

    Ok(Json(json!({
        "object": "send-fileDownload",
        "id": file_id,
        "url": url
    })))
}

#[derive(Debug, Deserialize)]
pub struct DownloadQuery {
    t: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SendDownloadClaims {
    sub: String,
    exp: usize,
}

async fn generate_download_token(
    state: &Arc<AppState>,
    send_id: &str,
    file_id: &str,
) -> Result<String, AppError> {
    let jwt_keys = state.jwt_keys.clone();
    let exp = (Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize;
    let claims = SendDownloadClaims {
        sub: format!("{send_id}/{file_id}"),
        exp,
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(jwt_keys.access_secret.as_bytes()),
    )?;
    Ok(token)
}

async fn validate_download_token(
    state: &Arc<AppState>,
    token: &str,
    send_id: &str,
    file_id: &str,
) -> Result<(), AppError> {
    let jwt_keys = state.jwt_keys.clone();
    let data = jsonwebtoken::decode::<SendDownloadClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(jwt_keys.access_secret.as_bytes()),
        &jsonwebtoken::Validation::default(),
    )
    .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    if data.claims.sub != format!("{send_id}/{file_id}") {
        return Err(AppError::Unauthorized("Invalid token".to_string()));
    }
    Ok(())
}

#[worker::send]
pub async fn download_send(
    State(state): State<Arc<AppState>>,
    Path((send_id, file_id)): Path<(String, String)>,
    Query(q): Query<DownloadQuery>,
) -> Result<Response, AppError> {
    validate_download_token(&state, &q.t, &send_id, &file_id).await?;
    let db = db::get_db(&state.env)?;
    let row: Option<Value> = db
        .prepare("SELECT * FROM send_files WHERE id = ?1 AND send_id = ?2 LIMIT 1")
        .bind(&[file_id.clone().into(), send_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let Some(row) = row else {
        return Err(AppError::NotFound("File not found".to_string()));
    };
    let file = serde_json::from_value::<SendFileDBModel>(row).map_err(|_| AppError::Internal)?;
    if file.storage_type.as_deref() != Some("r2") {
        return Err(AppError::NotFound("File not found".to_string()));
    }
    let object_key = file.r2_object_key.as_deref().ok_or(AppError::Internal)?;
    let bucket = state
        .env
        .bucket(SEND_FILES_BUCKET_BINDING)
        .map_err(|_| AppError::Internal)?;
    let object = bucket
        .get(object_key)
        .execute()
        .await
        .map_err(|_| AppError::Internal)?
        .ok_or_else(|| AppError::NotFound("File not found".to_string()))?;
    let object_size = object.size();
    let body = object
        .body()
        .ok_or(AppError::Internal)?
        .response_body()
        .map_err(|_| AppError::Internal)?;
    let worker_response = worker::Response::from_body(body).map_err(|_| AppError::Internal)?;
    let mut response: Response = worker_response.into();
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{}\"", file.file_name))
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("attachment")),
    );
    response.headers_mut().insert(
        r2_file::FIXED_LENGTH_HEADER,
        axum::http::HeaderValue::from_str(&object_size.to_string())
            .map_err(|_| AppError::Internal)?,
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::{
        hash_password, new_salt_b64, validate_deletion_date, validate_send_access,
        validate_send_lifetime,
    };
    use crate::db::models::send::{SEND_TYPE_TEXT, SendDBModel};
    use base64::{Engine as _, engine::general_purpose};
    use chrono::{SecondsFormat, Utc};

    #[test]
    fn send_password_hash_matches_vaultwarden_pbkdf2_sha256() {
        let salt = general_purpose::STANDARD.encode(b"salt");
        assert_eq!(
            hash_password("password", &salt, 1).expect("hash password"),
            "Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs="
        );
    }

    #[test]
    fn send_password_salt_matches_upstream_length() {
        let salt = general_purpose::STANDARD
            .decode(new_salt_b64())
            .expect("decode salt");
        assert_eq!(salt.len(), 64);
    }

    #[test]
    fn send_deletion_date_is_limited_to_31_days() {
        let valid =
            (Utc::now() + chrono::Duration::days(30)).to_rfc3339_opts(SecondsFormat::Millis, true);
        let invalid =
            (Utc::now() + chrono::Duration::days(32)).to_rfc3339_opts(SecondsFormat::Millis, true);
        assert!(validate_deletion_date(&valid).is_ok());
        assert!(validate_deletion_date(&invalid).is_err());
    }

    #[test]
    fn issued_send_token_remains_usable_at_access_limit() {
        let future =
            (Utc::now() + chrono::Duration::days(1)).to_rfc3339_opts(SecondsFormat::Millis, true);
        let send = SendDBModel {
            id: "send-id".to_string(),
            user_id: "user-id".to_string(),
            organization_id: None,
            r#type: SEND_TYPE_TEXT,
            name: "send".to_string(),
            notes: None,
            data: "{}".to_string(),
            key: "key".to_string(),
            password_hash: None,
            password_salt: None,
            password_iter: None,
            max_access_count: Some(1),
            access_count: 1,
            created_at: future.clone(),
            updated_at: future.clone(),
            expiration_date: None,
            deletion_date: future,
            disabled: false,
            hide_email: None,
        };

        assert!(validate_send_lifetime(&send).is_ok());
        assert!(validate_send_access(&send).is_err());
    }
}
