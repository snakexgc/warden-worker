use axum::{
    extract::{Path, State},
    http::HeaderMap,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::handlers::two_factor::{NumberOrString, PasswordOrOtpData};
use crate::notify::{self, NotifyContext, NotifyEvent};
use crate::router::AppState;
use crate::two_factor;

fn not_supported_response(message: &str) -> Response {
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

fn decode_base64_mixed(input: &str) -> Option<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .ok()
        .or_else(|| general_purpose::STANDARD.decode(input).ok())
}

fn parse_number_or_string_i32(input: NumberOrString) -> Result<i32, AppError> {
    match input {
        NumberOrString::Number(n) => Ok(n as i32),
        NumberOrString::String(s) => s
            .parse::<i32>()
            .map_err(|_| AppError::BadRequest("Invalid WebAuthn key id".to_string())),
    }
}

async fn validate_password_or_otp(
    payload: &PasswordOrOtpData,
    db: &worker::D1Database,
    user_id: &str,
) -> Result<(), AppError> {
    match (&payload.master_password_hash, &payload.otp) {
        (Some(master_password_hash), None) => {
            let row: Option<Value> = db
                .prepare("SELECT master_password_hash, password_salt FROM users WHERE id = ?1")
                .bind(&[user_id.into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Database)?;
            let row = row.ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
            let stored_hash = row
                .get("master_password_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let password_salt = row.get("password_salt").and_then(|v| v.as_str());

            let valid = if let Some(salt) = password_salt {
                crate::crypto::verify_password(master_password_hash, salt, stored_hash).await
            } else {
                constant_time_eq::constant_time_eq(
                    master_password_hash.as_bytes(),
                    stored_hash.as_bytes(),
                )
            };

            if valid {
                Ok(())
            } else {
                Err(AppError::Unauthorized("Invalid credentials".to_string()))
            }
        }
        (None, Some(_)) => Err(AppError::BadRequest(
            "OTP validation is not supported".to_string(),
        )),
        _ => Err(AppError::BadRequest("No validation provided".to_string())),
    }
}

#[worker::send]
pub async fn identity_assertion_options(State(_state): State<Arc<AppState>>) -> Response {
    not_supported_response("WebAuthn assertion is not supported in this deployment")
}

#[worker::send]
pub async fn attestation_options(_claims: Claims, State(_state): State<Arc<AppState>>) -> Response {
    not_supported_response("WebAuthn attestation is not supported in this deployment")
}

#[worker::send]
pub async fn assertion_options(_claims: Claims, State(_state): State<Arc<AppState>>) -> Response {
    not_supported_response("WebAuthn assertion is not supported in this deployment")
}

#[worker::send]
pub async fn list_credentials(
    _claims: Claims,
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn create_credential(_claims: Claims, State(_state): State<Arc<AppState>>) -> Response {
    not_supported_response("WebAuthn credential registration is not supported in this deployment")
}

#[worker::send]
pub async fn update_credential(
    _claims: Claims,
    State(_state): State<Arc<AppState>>,
    Path(_credential_id): Path<String>,
) -> Response {
    not_supported_response("WebAuthn credential update is not supported in this deployment")
}

#[worker::send]
pub async fn delete_credential(
    _claims: Claims,
    State(_state): State<Arc<AppState>>,
    Path(_credential_id): Path<String>,
) -> Response {
    not_supported_response("WebAuthn credential deletion is not supported in this deployment")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableWebauthnData {
    id: NumberOrString,
    name: String,
    device_response: Value,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteWebauthnData {
    id: NumberOrString,
    master_password_hash: String,
}

#[worker::send]
pub async fn two_factor_get_webauthn(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    validate_password_or_otp(&payload, &db, &claims.sub).await?;

    let (enabled, registrations) = two_factor::get_webauthn_credentials(&db, &claims.sub).await?;
    let keys = registrations
        .iter()
        .map(|r| json!({ "id": r.id, "name": r.name, "migrated": r.migrated }))
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "enabled": enabled,
        "keys": keys,
        "object": "twoFactorWebAuthn"
    })))
}

#[worker::send]
pub async fn two_factor_get_webauthn_challenge(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    validate_password_or_otp(&payload, &db, &claims.sub).await?;

    let creds = two_factor::get_webauthn_credentials(&db, &claims.sub)
        .await?
        .1
        .into_iter()
        .map(|r| r.credential_id)
        .collect::<Vec<_>>();

    let mut challenge_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge_bytes);
    let challenge = general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);
    let state_value = json!({
        "challenge": challenge,
        "kind": "webauthn.create"
    });

    let now = Utc::now().to_rfc3339();
    two_factor::upsert_webauthn_challenge(
        &db,
        &claims.sub,
        two_factor::TWO_FACTOR_TYPE_WEBAUTHN_REGISTER_CHALLENGE,
        &serde_json::to_string(&state_value).map_err(|_| AppError::Internal)?,
        &now,
    )
    .await?;

    let rp_id = state
        .env
        .var("DOMAIN")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_default()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or_default()
        .to_string();

    let mut challenge_value = json!({
        "challenge": state_value["challenge"],
        "rp": { "name": rp_id, "id": rp_id },
        "user": {
            "id": general_purpose::URL_SAFE_NO_PAD.encode(claims.sub.as_bytes()),
            "name": claims.email,
            "displayName": claims.name
        },
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },
            { "type": "public-key", "alg": -257 }
        ],
        "timeout": 60000,
        "attestation": "none",
        "excludeCredentials": creds.iter().map(|id| json!({
            "type": "public-key",
            "id": id
        })).collect::<Vec<_>>(),
        "authenticatorSelection": {
            "userVerification": "discouraged"
        }
    });
    challenge_value["status"] = Value::String("ok".to_string());
    challenge_value["errorMessage"] = Value::String(String::new());

    Ok(Json(challenge_value))
}

#[worker::send]
pub async fn two_factor_put_webauthn(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<EnableWebauthnData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let auth_payload = PasswordOrOtpData {
        master_password_hash: payload.master_password_hash,
        otp: payload.otp,
    };
    validate_password_or_otp(&auth_payload, &db, &claims.sub).await?;

    let register_state_raw = two_factor::take_webauthn_challenge(
        &db,
        &claims.sub,
        two_factor::TWO_FACTOR_TYPE_WEBAUTHN_REGISTER_CHALLENGE,
    )
    .await?
    .ok_or_else(|| AppError::BadRequest("Can't recover challenge".to_string()))?;

    let register_state: Value = serde_json::from_str(&register_state_raw).map_err(|_| AppError::Internal)?;
    let expected_challenge = register_state
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Can't recover challenge".to_string()))?;

    // Try "id" first, then "rawId" - "id" is usually base64url encoded, "rawId" might be double-encoded
    let credential_id = payload
        .device_response
        .get("id")
        .and_then(|v| v.as_str())
        .or_else(|| payload.device_response.get("rawId").and_then(|v| v.as_str()))
        .ok_or_else(|| AppError::BadRequest("WebAuthn credential id missing".to_string()))?
        .to_string();

    let attestation_object_b64 = payload
        .device_response
        .get("response")
        .and_then(|v| v.get("AttestationObject").or_else(|| v.get("attestationObject")))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("WebAuthn attestation object missing".to_string()))?;

    let client_data_b64 = payload
        .device_response
        .get("response")
        .and_then(|v| v.get("clientDataJson").or_else(|| v.get("clientDataJSON")))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("WebAuthn client data missing".to_string()))?;

    let client_data_raw = decode_base64_mixed(client_data_b64)
        .ok_or_else(|| AppError::BadRequest("WebAuthn client data invalid".to_string()))?;
    let client_data: Value = serde_json::from_slice(&client_data_raw)
        .map_err(|_| AppError::BadRequest("WebAuthn client data invalid".to_string()))?;

    let challenge = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("WebAuthn challenge missing".to_string()))?;
    let typ = client_data
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if challenge != expected_challenge {
        return Err(AppError::BadRequest(format!(
            "WebAuthn challenge mismatch: expected={}, got={}",
            expected_challenge, challenge
        )));
    }
    if typ != "webauthn.create" {
        return Err(AppError::BadRequest(format!(
            "WebAuthn type mismatch: expected=webauthn.create, got={}",
            typ
        )));
    }

    let (parsed_credential_id, public_key, sign_count, key_type) =
        two_factor::parse_webauthn_registration_attestation(attestation_object_b64)?;

    let raw_id_bytes = decode_base64_mixed(&credential_id)
        .ok_or_else(|| AppError::BadRequest(format!("WebAuthn credential id invalid: raw_id={}", credential_id)))?;
    let parsed_id_bytes = decode_base64_mixed(&parsed_credential_id)
        .ok_or_else(|| AppError::BadRequest(format!("WebAuthn parsed credential id invalid: parsed_id={}", parsed_credential_id)))?;
    if !constant_time_eq::constant_time_eq(&raw_id_bytes, &parsed_id_bytes) {
        return Err(AppError::BadRequest(format!(
            "WebAuthn credential id mismatch: raw_id_len={}, parsed_id_len={}",
            raw_id_bytes.len(), parsed_id_bytes.len()
        )));
    }

    let mut registrations = two_factor::get_webauthn_credentials(&db, &claims.sub).await?.1;
    registrations.push(two_factor::WebauthnCredentialRecord {
        id: parse_number_or_string_i32(payload.id)?,
        name: payload.name,
        migrated: false,
        credential_id: parsed_credential_id,
        public_key_sec1: Some(public_key),
        sign_count: Some(sign_count),
        key_type: Some(key_type),
    });

    let now = Utc::now().to_rfc3339();
    two_factor::upsert_webauthn_credentials(&db, &claims.sub, true, &registrations, &now).await?;
    let _ = two_factor::get_or_create_recovery_code(&db, &claims.sub).await?;

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorEnable,
        NotifyContext {
            user_id: Some(claims.sub.clone()),
            user_email: Some(claims.email.clone()),
            detail: Some("provider=webauthn".to_string()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );

    let keys = registrations
        .iter()
        .map(|r| json!({ "id": r.id, "name": r.name, "migrated": r.migrated }))
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "enabled": true,
        "keys": keys,
        "object": "twoFactorU2f"
    })))
}

#[worker::send]
pub async fn two_factor_delete_webauthn(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DeleteWebauthnData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let row: Option<Value> = db
        .prepare("SELECT master_password_hash, password_salt FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let row = row.ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let stored_hash = row.get("master_password_hash").and_then(|v| v.as_str()).unwrap_or("");
    let password_salt = row.get("password_salt").and_then(|v| v.as_str());

    let password_valid = if let Some(salt) = password_salt {
        crate::crypto::verify_password(&payload.master_password_hash, salt, stored_hash).await
    } else {
        constant_time_eq::constant_time_eq(
            payload.master_password_hash.as_bytes(),
            stored_hash.as_bytes(),
        )
    };
    if !password_valid {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let id = parse_number_or_string_i32(payload.id)?;
    let mut regs = two_factor::get_webauthn_credentials(&db, &claims.sub).await?.1;
    let idx = regs
        .iter()
        .position(|r| r.id == id)
        .ok_or_else(|| AppError::NotFound("WebAuthn entry not found".to_string()))?;
    regs.remove(idx);

    let now = Utc::now().to_rfc3339();
    two_factor::upsert_webauthn_credentials(&db, &claims.sub, true, &regs, &now).await?;

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorDisable,
        NotifyContext {
            user_id: Some(claims.sub.clone()),
            user_email: Some(claims.email.clone()),
            detail: Some("provider=webauthn".to_string()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );

    let keys = regs
        .iter()
        .map(|r| json!({ "id": r.id, "name": r.name, "migrated": r.migrated }))
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "enabled": true,
        "keys": keys,
        "object": "twoFactorU2f"
    })))
}
