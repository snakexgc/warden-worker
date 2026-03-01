use axum::{
    extract::{Multipart, Path, Query, State},
    http::HeaderMap,
    http::StatusCode,
    response::{Html, Response},
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use constant_time_eq::constant_time_eq;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;
use worker::query;

use crate::{
    auth::Claims,
    db,
    error::AppError,
    logging::targets,
    notify::{self, NotifyContext, NotifyEvent},
    router::AppState,
    models::send::{
        send_to_json, send_to_json_access, uuid_from_access_id, SendAccessData, SendDBModel,
        SendData, SendFileDBModel, SEND_TYPE_FILE, SEND_TYPE_TEXT,
    },
};

const SEND_FILES_BUCKET_BINDING: &str = "SEND_FILES_BUCKET";
const SEND_ACCESS_RATE_LIMITER_BINDING: &str = "SEND_ACCESS_LIMITER";

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
    Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>, AppError> {
    let dt = DateTime::parse_from_rfc3339(s).map_err(|_| AppError::BadRequest("Invalid date".to_string()))?;
    Ok(dt.with_timezone(&Utc))
}

fn request_client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("CF-Connecting-IP")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("X-Forwarded-For")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
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
        body.as_object_mut().unwrap().insert("remoteip".to_string(), Value::String(ip.to_string()));
    }

    let mut headers = worker::Headers::new();
    headers.set("Content-Type", "application/json").map_err(|_| AppError::Internal)?;
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
        Err(AppError::Unauthorized("Turnstile verification failed".to_string()))
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

/// Create a signed JWT cookie value valid for `SEND_ACCESS_COOKIE_TTL_MINUTES`.
fn generate_send_access_cookie(state: &Arc<AppState>) -> Result<String, AppError> {
    let secret = state.env.secret("JWT_SECRET")?.to_string();
    let now = Utc::now();
    let claims = SendAccessPassClaims {
        aud: "send_access".to_string(),
        iat: now.timestamp() as usize,
        exp: (now + chrono::Duration::minutes(SEND_ACCESS_COOKIE_TTL_MINUTES)).timestamp() as usize,
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}

/// Validate the signed cookie; returns `Ok(())` if valid.
fn validate_send_access_cookie(state: &Arc<AppState>, token: &str) -> Result<(), AppError> {
    let secret = state.env.secret("JWT_SECRET")?.to_string();
    let mut validation = jsonwebtoken::Validation::default();
    validation.set_audience(&["send_access"]);
    validation.set_required_spec_claims(&["exp", "aud"]);
    jsonwebtoken::decode::<SendAccessPassClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
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
fn require_send_access_pass(state: &Arc<AppState>, headers: &HeaderMap) -> Result<(), AppError> {
    if !turnstile_enabled(state) {
        return Ok(());
    }
    let token = extract_send_access_cookie(headers)
        .ok_or_else(|| AppError::Unauthorized("Turnstile verification required".to_string()))?;
    validate_send_access_cookie(state, &token)
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
pub async fn send_verify_page(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let site_key = state
        .env
        .var("TURNSTILE_SITE_KEY")
        .map(|v| v.to_string())
        .unwrap_or_default();

    let html = include_str!("../../static/send-verify.html")
        .replace(
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
             img-src 'self' data:"
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

    let cookie_value = generate_send_access_cookie(&state)?;
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
async fn check_storage_quota(db: &worker::D1Database, state: &Arc<AppState>, incoming_file_size: i64) -> Result<(), AppError> {
    // --- D1 check ---
    let d1_used: Option<i64> = db
        .prepare(
            "SELECT COALESCE(SUM(LENGTH(data)),0) \
             + (SELECT COALESCE(SUM(LENGTH(data)),0) FROM sends) \
             + (SELECT COALESCE(SUM(LENGTH(name)),0) FROM folders) \
             AS bytes FROM ciphers"
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

async fn enforce_send_access_rate_limit(state: &Arc<AppState>, key: String) -> Result<(), AppError> {
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

fn hash_password(password: &str, salt_b64: &str) -> Result<String, AppError> {
    let salt = general_purpose::STANDARD
        .decode(salt_b64)
        .map_err(|_| AppError::Internal)?;
    let mut hasher = Sha256::new();
    hasher.update(&salt);
    hasher.update(password.as_bytes());
    let out = hasher.finalize();
    Ok(general_purpose::STANDARD.encode(out))
}

fn new_salt_b64() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    general_purpose::STANDARD.encode(bytes)
}

fn extract_send_payload_data(mut data: SendData) -> Result<(i32, String, Value), AppError> {
    let send_type = data.r#type;
    let mut payload = match send_type {
        SEND_TYPE_TEXT => data.text.take().ok_or_else(|| AppError::BadRequest("Missing text".to_string()))?,
        SEND_TYPE_FILE => data.file.take().ok_or_else(|| AppError::BadRequest("Missing file".to_string()))?,
        _ => return Err(AppError::BadRequest("Invalid send type".to_string())),
    };

    if let Some(obj) = payload.as_object_mut() {
        obj.remove("response");
    }

    Ok((send_type, data.key, payload))
}

async fn get_send_by_id(db: &worker::D1Database, send_id: &str) -> Result<Option<SendDBModel>, AppError> {
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

async fn update_send_access_count(db: &worker::D1Database, send_id: &str, delta: i32) -> Result<(), AppError> {
    db.prepare("UPDATE sends SET access_count = access_count + ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[
            delta.into(),
            now_rfc3339_millis().into(),
            send_id.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(())
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

fn validate_send_access(send: &SendDBModel) -> Result<(), AppError> {
    if send.disabled {
        return Err(AppError::NotFound("Send not found".to_string()));
    }

    if let Some(max_access_count) = send.max_access_count {
        if send.access_count >= max_access_count {
            return Err(AppError::NotFound("Send not found".to_string()));
        }
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
    let candidate = hash_password(&password, stored_salt_b64)?;
    if !constant_time_eq(stored_hash_b64.as_bytes(), candidate.as_bytes()) {
        log::warn!(target: targets::AUTH, "send.password_check.fail send_id={} reason=password_mismatch", send.id);
        return Err(AppError::BadRequest("Invalid password".to_string()));
    }
    log::debug!(target: targets::AUTH, "send.password_check.ok send_id={}", send.id);
    Ok(())
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

    if owned.r#type == SEND_TYPE_FILE {
        let file_rows: Vec<Value> = db
            .prepare("SELECT r2_object_key, storage_type FROM send_files WHERE send_id = ?1 AND user_id = ?2")
            .bind(&[send_id.clone().into(), claims.sub.clone().into()])?
            .all()
            .await
            .map_err(|_| AppError::Database)?
            .results()?;

        if let Ok(bucket) = state.env.bucket(SEND_FILES_BUCKET_BINDING) {
            for row in file_rows {
                let storage_type = row
                    .get("storage_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("d1_base64");
                if storage_type != "r2" {
                    continue;
                }
                if let Some(key) = row.get("r2_object_key").and_then(|v| v.as_str()) {
                    let _ = bucket.delete(key.to_string()).await;
                }
            }
        }

        query!(
            &db,
            "DELETE FROM send_files WHERE send_id = ?1 AND user_id = ?2",
            send_id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
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

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::SendDelete,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            send_id: Some(send_id),
            detail: Some(format!("type={}", owned.r#type)),
            meta,
            ..Default::default()
        },
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

    if payload.r#type == SEND_TYPE_FILE {
        return Err(AppError::BadRequest("File sends should use /api/sends/file/v2".to_string()));
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

    let payload = payload;
    let name = payload.name.clone();
    let notes = payload.notes.clone();
    let password = payload.password.clone();
    let max_access_count = payload.max_access_count;
    let expiration_date = payload.expiration_date.clone();
    let deletion_date = payload.deletion_date.clone();
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
        (Some(p), Some(salt)) if !p.trim().is_empty() => Some(hash_password(p, salt)?),
        _ => None,
    };

    let data_str = serde_json::to_string(&data_value).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "INSERT INTO sends (id, user_id, organization_id, type, name, notes, data, key, password_hash, password_salt, password_iter, max_access_count, access_count, created_at, updated_at, expiration_date, deletion_date, disabled, hide_email)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, 0, ?11, ?12, ?13, ?14, ?15, ?16)",
        send_id,
        claims.sub,
        send_type,
        name,
        notes,
        data_str,
        key,
        password_hash,
        password_salt,
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

    let payload = payload;
    let name = payload.name.clone();
    let notes = payload.notes.clone();
    let max_access_count = payload.max_access_count;
    let expiration_date = payload.expiration_date.clone();
    let deletion_date = payload.deletion_date.clone();
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

    if let Some(password) = payload.password.as_deref() {
        let salt = new_salt_b64();
        let hash = hash_password(password, &salt)?;
        password_hash = Some(hash);
        password_salt = Some(salt);
        password_iter = None;
    }

    log::info!(
        target: targets::API,
        "send.update.password_apply send_id={} has_password_key={} apply_new_password={} keep_existing_password={}",
        send_id,
        has_password_key,
        payload.password.as_deref().is_some(),
        payload.password.as_deref().is_none()
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

    query!(
        &db,
        "UPDATE sends
         SET password_hash = NULL,
             password_salt = NULL,
             password_iter = NULL,
             updated_at = ?1
         WHERE id = ?2 AND user_id = ?3",
        now_rfc3339_millis(),
        send_id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let send = get_send_by_id_and_user(&db, &existing.id, &existing.user_id)
        .await?
        .ok_or_else(|| AppError::Internal)?;

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
    headers: HeaderMap,
    Json(payload): Json<SendData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    if payload.r#type != SEND_TYPE_FILE {
        return Err(AppError::BadRequest("Send content is not a file".to_string()));
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
    if file_length < 0 {
        return Err(AppError::BadRequest("Send size can't be negative".to_string()));
    }

    // Reject early if D1 or R2 is nearly full
    check_storage_quota(&db, &state, file_length).await?;

    let name = payload.name.clone();
    let notes = payload.notes.clone();
    let max_access_count = payload.max_access_count;
    let expiration_date = payload.expiration_date.clone();
    let deletion_date = payload.deletion_date.clone();
    let disabled = payload.disabled;
    let hide_email = payload.hide_email;

    let (send_type, key, mut data_value) = extract_send_payload_data(payload)?;

    let file_id = Uuid::new_v4().to_string();
    if let Some(obj) = data_value.as_object_mut() {
        obj.insert("id".to_string(), Value::String(file_id.clone()));
        obj.insert("size".to_string(), Value::Number(file_length.into()));
        obj.insert("sizeName".to_string(), Value::String(display_size(file_length)));
    }

    let send_id = Uuid::new_v4().to_string();
    let now = now_rfc3339_millis();
    let data_str = serde_json::to_string(&data_value).map_err(|_| AppError::Internal)?;
    let object_key = format!("sends/{}/{}/{}", claims.sub, send_id, file_id);

    query!(
        &db,
        "INSERT INTO sends (id, user_id, organization_id, type, name, notes, data, key, password_hash, password_salt, password_iter, max_access_count, access_count, created_at, updated_at, expiration_date, deletion_date, disabled, hide_email)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, NULL, NULL, NULL, ?8, 0, ?9, ?10, ?11, ?12, ?13, ?14)",
        send_id,
        claims.sub,
        send_type,
        name,
        notes,
        data_str,
        key,
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
        file_length,
        object_key,
        "r2",
        now,
        now
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

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

    let send_id_for_notify = send_id.clone();
    let file_name = data_value
        .get("fileName")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "file".to_string());

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::SendCreate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            send_id: Some(send_id_for_notify),
            detail: Some(format!("type={send_type}, file={file_name}")),
            meta,
            ..Default::default()
        },
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
    Path((send_id, file_id)): Path<(String, String)>,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let send = get_send_by_id_and_user(&db, &send_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("Send not found. Unable to save the file.".to_string()))?;
    if send.r#type != SEND_TYPE_FILE {
        return Err(AppError::BadRequest("Send content is not a file".to_string()));
    }

    let file_row: Option<Value> = db
        .prepare("SELECT size, r2_object_key, storage_type FROM send_files WHERE id = ?1 AND send_id = ?2 AND user_id = ?3 LIMIT 1")
        .bind(&[file_id.clone().into(), send_id.clone().into(), claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let file_row = file_row.ok_or_else(|| AppError::NotFound("Send not found. Unable to save the file.".to_string()))?;
    let size = file_row
        .get("size")
        .and_then(|v| v.as_i64())
        .ok_or(AppError::Internal)?;
    if size < 0 {
        return Err(AppError::BadRequest("Send size can't be negative".to_string()));
    }
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
        return Err(AppError::BadRequest("Send storage backend mismatch".to_string()));
    }

    let now = now_rfc3339_millis();
    let expected_size = size as usize;
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

        uploaded = true;

        let mut bytes = Vec::with_capacity(expected_size);
        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|e| AppError::BadRequest(format!("Invalid multipart data: {e}")))?
        {
            bytes.extend_from_slice(&chunk);
        }

        if bytes.len() != expected_size {
            return Err(AppError::BadRequest("Uploaded size mismatch".to_string()));
        }

        bucket
            .put(object_key.clone(), bytes)
            .execute()
            .await
            .map_err(|_| AppError::Internal)?;

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
        .await?;

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

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_access(
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
    require_send_access_pass(&state, &headers)?;
    enforce_send_access_rate_limit(
        &state,
        format!(
            "send_access:{}:{}",
            access_id,
            client_ip.as_deref().unwrap_or("unknown")
        ),
    )
    .await?;

    let send_id = uuid_from_access_id(&access_id).ok_or_else(|| AppError::NotFound("Send not found".to_string()))?;
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
        update_send_access_count(&db, &send.id, 1).await?;
    }

    let creator_identifier = get_creator_identifier(&db, &send).await?;
    log::info!(target: targets::AUTH, "send.access.success send_id={} type={}", send.id, send.r#type);
    Ok(Json(send_to_json_access(&send, creator_identifier)))
}

#[worker::send]
pub async fn post_access_file(
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
    // Require Turnstile send-access pass (cookie set by /send-verify flow)
    require_send_access_pass(&state, &headers)?;
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

    update_send_access_count(&db, &send.id, 1).await?;

    let token = generate_download_token(&state, &send_id, &file_id)?;
    let url = format!("/api/sends/{send_id}/{file_id}?t={token}");

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

fn generate_download_token(state: &Arc<AppState>, send_id: &str, file_id: &str) -> Result<String, AppError> {
    let secret = state.env.secret("JWT_SECRET")?.to_string();
    let exp = (Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize;
    let claims = SendDownloadClaims {
        sub: format!("{send_id}/{file_id}"),
        exp,
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}

fn validate_download_token(state: &Arc<AppState>, token: &str, send_id: &str, file_id: &str) -> Result<(), AppError> {
    let secret = state.env.secret("JWT_SECRET")?.to_string();
    let data = jsonwebtoken::decode::<SendDownloadClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
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
    validate_download_token(&state, &q.t, &send_id, &file_id)?;
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
    let body = object.body().ok_or(AppError::Internal)?;
    let bytes = body.bytes().await.map_err(|_| AppError::Internal)?;

    let mut response = Response::new(axum::body::Body::from(bytes));
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
    Ok(response)
}
