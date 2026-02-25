use axum::{extract::State, http::{HeaderMap, StatusCode}, response::{IntoResponse, Response}, Json};
use axum::extract::{Path, Query};
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
use constant_time_eq::constant_time_eq;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;
use worker::wasm_bindgen::JsValue;

use crate::{auth::Claims, db, error::AppError, router::AppState};

async fn ensure_devices_table(db: &worker::D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            device_identifier TEXT NOT NULL,
            device_name TEXT,
            device_type INTEGER,
            remember_token_hash TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, device_identifier),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    let _ = db
        .prepare("ALTER TABLE devices ADD COLUMN remember_token_hash TEXT")
        .run()
        .await;
    Ok(())
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}

fn header_i64(headers: &HeaderMap, name: &str) -> Option<i64> {
    header_str(headers, name)?.trim().parse::<i64>().ok()
}

fn infer_device_name(headers: &HeaderMap) -> Option<String> {
    let client = header_str(headers, "bitwarden-client-name")
        .or_else(|| header_str(headers, "Bitwarden-Client-Name"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let ver = header_str(headers, "bitwarden-client-version")
        .or_else(|| header_str(headers, "Bitwarden-Client-Version"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    match (client, ver) {
        (Some(c), Some(v)) => Some(format!("{c} {v}")),
        (Some(c), None) => Some(c),
        _ => None,
    }
}

fn infer_device_type(headers: &HeaderMap) -> Option<i64> {
    header_i64(headers, "device-type").or_else(|| header_i64(headers, "Device-Type"))
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

#[worker::send]
pub async fn knowndevice(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    ensure_devices_table(&db).await?;

    let email_b64 = headers
        .get("x-request-email")
        .or_else(|| headers.get("X-Request-Email"))
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("X-Request-Email value is required".to_string()))?;
    let device_identifier = headers
        .get("x-device-identifier")
        .or_else(|| headers.get("X-Device-Identifier"))
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("X-Device-Identifier value is required".to_string()))?;

    let email_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(email_b64.as_bytes())
        .map_err(|_| AppError::BadRequest("X-Request-Email value failed to decode as base64url".to_string()))?;
    let email = String::from_utf8(email_bytes)
        .map_err(|_| AppError::BadRequest("X-Request-Email value failed to decode as UTF-8".to_string()))?
        .to_lowercase();

    let user_id: Option<String> = db
        .prepare("SELECT id FROM users WHERE email = ?1")
        .bind(&[email.into()])?
        .first(Some("id"))
        .await
        .map_err(|_| AppError::Database)?;

    let Some(user_id) = user_id else {
        return Ok(Json(json!(false)));
    };

    let exists: Option<i64> = db
        .prepare("SELECT 1 AS ok FROM devices WHERE user_id = ?1 AND device_identifier = ?2 LIMIT 1")
        .bind(&[user_id.into(), device_identifier.into()])?
        .first(Some("ok"))
        .await
        .map_err(|_| AppError::Database)?;

    Ok(Json(json!(exists.is_some())))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushTokenRequest {
    #[allow(dead_code)]
    push_token: String,
}

#[worker::send]
pub async fn device_token(
    claims: Claims,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(device_identifier): Path<String>,
    Json(_payload): Json<PushTokenRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    ensure_devices_table(&db).await?;

    let inferred_name = infer_device_name(&headers);
    let inferred_type = infer_device_type(&headers);
    let now = Utc::now().to_rfc3339();

    db.prepare(
        "INSERT INTO devices (id, user_id, device_identifier, device_name, device_type, remember_token_hash, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)
         ON CONFLICT(user_id, device_identifier) DO UPDATE SET
           updated_at = excluded.updated_at,
           device_name = COALESCE(excluded.device_name, devices.device_name),
           device_type = COALESCE(excluded.device_type, devices.device_type)",
    )
    .bind(&[
        Uuid::new_v4().to_string().into(),
        claims.sub.into(),
        device_identifier.into(),
        js_opt_string(inferred_name),
        js_opt_i64(inferred_type),
        now.clone().into(),
        now.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(Json(()))
}

#[worker::send]
pub async fn get_devices(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    ensure_device_management_tables(&db).await?;
    purge_expired_auth_requests(&db).await?;

    let rows: Vec<Value> = db
        .prepare(
            "SELECT id, device_identifier, device_name, device_type, remember_token_hash, created_at, updated_at,
                (
                    SELECT ar.id
                    FROM auth_requests ar
                    WHERE ar.user_id = devices.user_id
                      AND ar.request_device_identifier = devices.device_identifier
                      AND ar.approved IS NULL
                    ORDER BY ar.creation_date DESC
                    LIMIT 1
                ) AS pending_auth_request_id,
                (
                    SELECT ar.creation_date
                    FROM auth_requests ar
                    WHERE ar.user_id = devices.user_id
                      AND ar.request_device_identifier = devices.device_identifier
                      AND ar.approved IS NULL
                    ORDER BY ar.creation_date DESC
                    LIMIT 1
                ) AS pending_auth_request_creation_date
             FROM devices
             WHERE user_id = ?1
             ORDER BY updated_at DESC",
        )
        .bind(&[claims.sub.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;

    let data = rows
        .into_iter()
        .map(|row| {
            let id = row.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let identifier = row
                .get("device_identifier")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = row
                .get("device_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let device_type = row.get("device_type").and_then(|v| v.as_i64()).unwrap_or(0);
            let created_at = row
                .get("created_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let updated_at = row
                .get("updated_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let trusted = row
                .get("remember_token_hash")
                .and_then(|v| v.as_str())
                .is_some();

            let pending_id = row
                .get("pending_auth_request_id")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let pending_creation = row
                .get("pending_auth_request_creation_date")
                .and_then(|v| v.as_str())
                .map(str::to_string);

            let pending = match (pending_id, pending_creation) {
                (Some(id), Some(creation_date)) => json!({
                    "id": id,
                    "creationDate": creation_date,
                }),
                _ => Value::Null,
            };

            json!({
                "id": id,
                "name": name,
                "identifier": identifier,
                "type": device_type,
                "creationDate": created_at,
                "revisionDate": updated_at,
                "lastSeenDate": updated_at,
                "isTrusted": trusted,
                "devicePendingAuthRequest": pending,
                "object": "device"
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "data": data,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn get_device_by_identifier(
    claims: Claims,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(device_identifier): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    ensure_devices_table(&db).await?;

    let inferred_name = infer_device_name(&headers);
    let inferred_type = infer_device_type(&headers);
    let row: Option<Value> = db
        .prepare(
            "SELECT id, device_identifier, device_name, device_type, remember_token_hash, created_at, updated_at
             FROM devices
             WHERE user_id = ?1 AND device_identifier = ?2
             LIMIT 1",
        )
        .bind(&[claims.sub.clone().into(), device_identifier.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let now = Utc::now().to_rfc3339();
    let row = match row {
        Some(row) => row,
        None => {
            let device_id = Uuid::new_v4().to_string();
            db.prepare(
                "INSERT INTO devices (id, user_id, device_identifier, device_name, device_type, remember_token_hash, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)",
            )
            .bind(&[
                device_id.clone().into(),
                claims.sub.clone().into(),
                device_identifier.clone().into(),
                js_opt_string(inferred_name.clone()),
                js_opt_i64(inferred_type),
                now.clone().into(),
                now.clone().into(),
            ])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;

            db.prepare(
                "SELECT id, device_identifier, device_name, device_type, remember_token_hash, created_at, updated_at
                 FROM devices
                 WHERE id = ?1
                 LIMIT 1",
            )
            .bind(&[device_id.into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?
            .ok_or(AppError::Internal)?
        }
    };

    let row_device_type = row.get("device_type").and_then(|v| v.as_i64());
    let row_device_name = row
        .get("device_name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let row_id = row.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let row_created_at = row
        .get("created_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let row_updated_at = row
        .get("updated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let should_update_type = row_device_type.is_none() && inferred_type.is_some();
    let should_update_name = row_device_name
        .as_deref()
        .map(|s| s.trim().is_empty())
        .unwrap_or(true)
        && inferred_name.is_some();
    let updated = should_update_type || should_update_name;
    if updated {
        let update_name = inferred_name.clone().or(row_device_name.clone());
        let update_type = inferred_type.or(row_device_type);
        let _ = db
            .prepare("UPDATE devices SET device_name = ?1, device_type = ?2, updated_at = ?3 WHERE id = ?4")
            .bind(&[
                js_opt_string(update_name),
                js_opt_i64(update_type),
                now.clone().into(),
                row_id.clone().into(),
            ])
            .map_err(|_| AppError::Database)?
            .run()
            .await;
    }

    let identifier = row
        .get("device_identifier")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let name = inferred_name.or(row_device_name).unwrap_or_default();
    let device_type = inferred_type.or(row_device_type).unwrap_or(0);
    let created_at = row_created_at;
    let updated_at = if updated { now.clone() } else { row_updated_at };
    let trusted = row
        .get("remember_token_hash")
        .and_then(|v| v.as_str())
        .is_some();

    Ok(Json(json!({
        "id": row_id,
        "name": name,
        "identifier": identifier,
        "type": device_type,
        "creationDate": created_at,
        "revisionDate": updated_at,
        "lastSeenDate": updated_at,
        "isTrusted": trusted,
        "object": "device"
    })))
}

pub(crate) async fn ensure_auth_requests_table(db: &worker::D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS auth_requests (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            request_device_identifier TEXT NOT NULL,
            device_type INTEGER NOT NULL,
            request_ip TEXT NOT NULL,
            response_device_identifier TEXT,
            access_code_hash TEXT NOT NULL,
            public_key TEXT NOT NULL,
            enc_key TEXT,
            master_password_hash TEXT,
            approved INTEGER,
            creation_date TEXT NOT NULL,
            response_date TEXT,
            authentication_date TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    db.prepare("CREATE INDEX IF NOT EXISTS idx_auth_requests_user_id ON auth_requests(user_id)")
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    Ok(())
}

pub(crate) async fn ensure_device_management_tables(db: &worker::D1Database) -> Result<(), AppError> {
    ensure_devices_table(db).await?;
    ensure_auth_requests_table(db).await?;
    Ok(())
}

pub(crate) async fn purge_expired_auth_requests(db: &worker::D1Database) -> Result<(), AppError> {
    let cutoff = (Utc::now() - Duration::minutes(15)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    db.prepare("DELETE FROM auth_requests WHERE creation_date < ?1")
        .bind(&[cutoff.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(())
}

fn client_ip_from_headers(headers: &HeaderMap) -> String {
    if let Some(ip) = headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("CF-Connecting-IP"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return ip.to_string();
    }

    if let Some(ip) = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("X-Forwarded-For"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return ip.to_string();
    }

    "0.0.0.0".to_string()
}

fn origin_from_headers(headers: &HeaderMap) -> String {
    let proto = headers
        .get("x-forwarded-proto")
        .or_else(|| headers.get("X-Forwarded-Proto"))
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("https");
    let host = headers
        .get("host")
        .or_else(|| headers.get("Host"))
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("localhost");
    format!("{proto}://{host}")
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn device_type_to_string(device_type: i32) -> &'static str {
    match device_type {
        0 => "Android",
        1 => "iOS",
        2 => "Chrome Extension",
        3 => "Firefox Extension",
        4 => "Opera Extension",
        5 => "Edge Extension",
        6 => "Windows",
        7 => "macOS",
        8 => "Linux",
        9 => "Chrome",
        10 => "Firefox",
        11 => "Opera",
        12 => "Edge",
        13 => "Internet Explorer",
        15 => "Android",
        16 => "UWP",
        17 => "Safari",
        18 => "Vivaldi",
        19 => "Vivaldi Extension",
        20 => "Safari Extension",
        21 => "SDK",
        22 => "Server",
        23 => "Windows CLI",
        24 => "macOS CLI",
        25 => "Linux CLI",
        _ => "Unknown Browser",
    }
}

fn value_to_bool(value: Option<&Value>) -> Option<bool> {
    value.and_then(|v| {
        if v.is_null() {
            None
        } else if let Some(b) = v.as_bool() {
            Some(b)
        } else if let Some(i) = v.as_i64() {
            Some(i != 0)
        } else if let Some(s) = v.as_str() {
            match s {
                "1" | "true" | "TRUE" => Some(true),
                "0" | "false" | "FALSE" => Some(false),
                _ => None,
            }
        } else {
            None
        }
    })
}

fn auth_request_to_json(row: &Value, origin: &str) -> Value {
    let approved = value_to_bool(row.get("approved"));
    let request_device_type = row
        .get("device_type")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .unwrap_or(14);
    let request_device_identifier = row
        .get("request_device_identifier")
        .cloned()
        .unwrap_or(Value::Null);
    let request_device_id = row
        .get("response_device_identifier")
        .cloned()
        .or_else(|| row.get("request_device_identifier").cloned())
        .unwrap_or(Value::Null);

    json!({
        "id": row.get("id").cloned().unwrap_or(Value::Null),
        "publicKey": row.get("public_key").cloned().unwrap_or(Value::Null),
        "requestDeviceType": device_type_to_string(request_device_type),
        "requestDeviceTypeValue": request_device_type,
        "requestDeviceIdentifier": request_device_identifier,
        "requestDeviceId": request_device_id,
        "requestIpAddress": row.get("request_ip").cloned().unwrap_or(Value::Null),
        "requestCountryName": Value::Null,
        "key": row.get("enc_key").cloned().unwrap_or(Value::Null),
        "masterPasswordHash": row.get("master_password_hash").cloned().unwrap_or(Value::Null),
        "creationDate": row.get("creation_date").cloned().unwrap_or(Value::Null),
        "responseDate": row.get("response_date").cloned().unwrap_or(Value::Null),
        "requestApproved": approved,
        "origin": origin,
        "object": "auth-request"
    })
}

fn to_js_val<T: Into<JsValue>>(val: Option<T>) -> JsValue {
    val.map(Into::into).unwrap_or(JsValue::NULL)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthRequestRequest {
    access_code: String,
    device_identifier: String,
    email: String,
    public_key: String,
}

#[worker::send]
pub async fn post_auth_request(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthRequestRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    ensure_device_management_tables(&db).await?;
    purge_expired_auth_requests(&db).await?;

    let email = payload.email.trim().to_lowercase();
    let user_id: Option<String> = db
        .prepare("SELECT id FROM users WHERE email = ?1")
        .bind(&[email.into()])?
        .first(Some("id"))
        .await
        .map_err(|_| AppError::Database)?;
    let Some(user_id) = user_id else {
        return Err(AppError::BadRequest(
            "AuthRequest doesn't exist".to_string(),
        ));
    };

    let req_device_type = infer_device_type(&headers).unwrap_or(14) as i32;
    let existing_device_type: Option<i64> = db
        .prepare(
            "SELECT device_type
             FROM devices
             WHERE user_id = ?1 AND device_identifier = ?2
             LIMIT 1",
        )
        .bind(&[
            user_id.clone().into(),
            payload.device_identifier.clone().into(),
        ])?
        .first(Some("device_type"))
        .await
        .map_err(|_| AppError::Database)?;

    if existing_device_type.map(|v| v as i32) != Some(req_device_type) {
        return Err(AppError::BadRequest(
            "AuthRequest doesn't exist".to_string(),
        ));
    }

    let request_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let request_ip = client_ip_from_headers(&headers);
    let access_code_hash = sha256_hex(&payload.access_code);
    let request_device_identifier = payload.device_identifier.clone();
    let request_public_key = payload.public_key.clone();
    db.prepare(
        "INSERT INTO auth_requests (
            id, user_id, request_device_identifier, device_type, request_ip,
            response_device_identifier, access_code_hash, public_key, enc_key,
            master_password_hash, approved, creation_date, response_date, authentication_date
         ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, NULL, NULL, NULL, ?8, NULL, NULL)",
    )
    .bind(&[
        request_id.clone().into(),
        user_id.clone().into(),
        request_device_identifier.clone().into(),
        req_device_type.into(),
        request_ip.into(),
        access_code_hash.into(),
        request_public_key.clone().into(),
        now.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    let notify_request_id = request_id.clone();
    let env = state.env.clone();
    state.ctx.wait_until(async move {
        if let Err(e) = crate::notifications::publish_auth_request(&env, &user_id, &notify_request_id).await {
            log::warn!("publish auth request realtime failed: {e}");
        }
        if let Err(e) = crate::notify::publish_auth_request(&env, &user_id, &notify_request_id).await {
            log::warn!("publish auth request notify failed: {e}");
        }
    });

    Ok(Json(json!({
        "id": request_id,
        "publicKey": request_public_key,
        "requestDeviceType": device_type_to_string(req_device_type),
        "requestDeviceTypeValue": req_device_type,
        "requestDeviceIdentifier": request_device_identifier,
        "requestDeviceId": Value::Null,
        "requestIpAddress": client_ip_from_headers(&headers),
        "requestCountryName": Value::Null,
        "key": Value::Null,
        "masterPasswordHash": Value::Null,
        "creationDate": now,
        "responseDate": Value::Null,
        "requestApproved": false,
        "origin": origin_from_headers(&headers),
        "object": "auth-request"
    })))
}

#[worker::send]
pub async fn get_auth_request(
    headers: HeaderMap,
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(auth_request_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    ensure_auth_requests_table(&db).await?;
    purge_expired_auth_requests(&db).await?;

    let row: Option<Value> = db
        .prepare("SELECT * FROM auth_requests WHERE id = ?1 AND user_id = ?2 LIMIT 1")
        .bind(&[auth_request_id.into(), claims.sub.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let Some(row) = row else {
        return Err(AppError::BadRequest(
            "AuthRequest doesn't exist".to_string(),
        ));
    };

    Ok(Json(auth_request_to_json(
        &row,
        &origin_from_headers(&headers),
    )))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponseRequest {
    device_identifier: String,
    key: String,
    master_password_hash: Option<String>,
    request_approved: bool,
}

#[worker::send]
pub async fn put_auth_request(
    headers: HeaderMap,
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(auth_request_id): Path<String>,
    Json(payload): Json<AuthResponseRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    ensure_device_management_tables(&db).await?;
    purge_expired_auth_requests(&db).await?;
    let user_id = claims.sub.clone();

    let row: Option<Value> = db
        .prepare("SELECT * FROM auth_requests WHERE id = ?1 AND user_id = ?2 LIMIT 1")
        .bind(&[auth_request_id.clone().into(), user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let Some(row) = row else {
        return Err(AppError::BadRequest(
            "AuthRequest doesn't exist".to_string(),
        ));
    };

    if value_to_bool(row.get("approved")).is_some() {
        return Err(AppError::BadRequest(
            "An authentication request with the same device already exists".to_string(),
        ));
    }

    let approver_device_identifier = payload.device_identifier.trim();
    if approver_device_identifier.is_empty() {
        return Err(AppError::BadRequest(
            "AuthRequest doesn't exist".to_string(),
        ));
    }
    if let Some(claim_device_identifier) = claims.device.as_deref() {
        if claim_device_identifier != approver_device_identifier {
            return Err(AppError::BadRequest(
                "AuthRequest doesn't exist".to_string(),
            ));
        }
    }

    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let origin = origin_from_headers(&headers);
    let response_device_identifier = approver_device_identifier.to_string();
    let master_password_hash = to_js_val(payload.master_password_hash.clone());

    if payload.request_approved {
        db.prepare(
            "UPDATE auth_requests
             SET approved = 1,
                 enc_key = ?1,
                 master_password_hash = ?2,
                 response_device_identifier = ?3,
                 response_date = ?4
             WHERE id = ?5 AND user_id = ?6",
        )
        .bind(&[
            payload.key.into(),
            master_password_hash,
            response_device_identifier.into(),
            now.clone().into(),
            auth_request_id.clone().into(),
            user_id.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

        let env = state.env.clone();
        let uid = user_id.clone();
        let rid = auth_request_id.clone();
        state.ctx.wait_until(async move {
            if let Err(e) = crate::notifications::publish_auth_response(&env, &uid, &rid).await {
                log::warn!("publish auth response realtime failed: {e}");
            }
            if let Err(e) = crate::notify::publish_auth_response(&env, &uid, &rid).await {
                log::warn!("publish auth response notify failed: {e}");
            }
        });

        let updated: Option<Value> = db
            .prepare("SELECT * FROM auth_requests WHERE id = ?1 LIMIT 1")
            .bind(&[auth_request_id.clone().into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;
        let Some(updated) = updated else {
            return Err(AppError::Database);
        };
        return Ok(Json(auth_request_to_json(&updated, &origin)));
    }

    db.prepare("DELETE FROM auth_requests WHERE id = ?1 AND user_id = ?2")
        .bind(&[auth_request_id.clone().into(), user_id.clone().into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    let env = state.env.clone();
    let uid = user_id.clone();
    let rid = auth_request_id.clone();
    state.ctx.wait_until(async move {
        if let Err(e) = crate::notifications::publish_auth_response(&env, &uid, &rid).await {
            log::warn!("publish auth response realtime failed: {e}");
        }
        if let Err(e) = crate::notify::publish_auth_response(&env, &uid, &rid).await {
            log::warn!("publish auth response notify failed: {e}");
        }
    });

    let request_device_type = row
        .get("device_type")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .unwrap_or(14);
    Ok(Json(json!({
        "id": auth_request_id,
        "publicKey": row.get("public_key").cloned().unwrap_or(Value::Null),
        "requestDeviceType": device_type_to_string(request_device_type),
        "requestDeviceTypeValue": request_device_type,
        "requestDeviceIdentifier": row.get("request_device_identifier").cloned().unwrap_or(Value::Null),
        "requestDeviceId": row.get("request_device_identifier").cloned().unwrap_or(Value::Null),
        "requestIpAddress": row.get("request_ip").cloned().unwrap_or(Value::Null),
        "requestCountryName": Value::Null,
        "key": Value::Null,
        "masterPasswordHash": Value::Null,
        "creationDate": row.get("creation_date").cloned().unwrap_or(Value::Null),
        "responseDate": now,
        "requestApproved": false,
        "origin": origin,
        "object": "auth-request"
    })))
}

#[derive(Debug, Deserialize)]
pub struct AuthRequestResponseQuery {
    code: String,
}

fn auth_request_not_exist_response() -> Response {
    let message = "AuthRequest doesn't exist";
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "message": message,
            "validationErrors": {
                "": [message]
            },
            "errorModel": {
                "message": message,
                "object": "error"
            },
            "error": "",
            "error_description": "",
            "exceptionMessage": Value::Null,
            "exceptionStackTrace": Value::Null,
            "innerExceptionMessage": Value::Null,
            "object": "error"
        })),
    )
        .into_response()
}

#[worker::send]
pub async fn get_auth_request_response(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(auth_request_id): Path<String>,
    Query(query): Query<AuthRequestResponseQuery>,
) -> Result<Response, AppError> {
    let db = db::get_db(&state.env)?;
    ensure_auth_requests_table(&db).await?;
    purge_expired_auth_requests(&db).await?;

    let row: Option<Value> = db
        .prepare("SELECT * FROM auth_requests WHERE id = ?1 LIMIT 1")
        .bind(&[auth_request_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let Some(row) = row else {
        return Ok(auth_request_not_exist_response());
    };

    let row_code_hash = row
        .get("access_code_hash")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let query_code_hash = sha256_hex(&query.code);

    if !constant_time_eq(row_code_hash.as_bytes(), query_code_hash.as_bytes()) {
        return Ok(auth_request_not_exist_response());
    }

    Ok(Json(auth_request_to_json(
        &row,
        &origin_from_headers(&headers),
    ))
    .into_response())
}

#[worker::send]
pub async fn get_auth_requests(
    headers: HeaderMap,
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    get_auth_requests_pending(headers, claims, State(state)).await
}

#[worker::send]
pub async fn get_auth_requests_pending(
    headers: HeaderMap,
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    ensure_auth_requests_table(&db).await?;
    purge_expired_auth_requests(&db).await?;

    let rows: Vec<Value> = db
        .prepare(
            "SELECT *
             FROM auth_requests
             WHERE user_id = ?1 AND approved IS NULL
             ORDER BY creation_date DESC",
        )
        .bind(&[claims.sub.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;

    let origin = origin_from_headers(&headers);
    let data = rows
        .iter()
        .map(|row| auth_request_to_json(row, &origin))
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "data": data,
        "continuationToken": Value::Null,
        "object": "list"
    })))
}
